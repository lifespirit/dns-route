package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"database/sql"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/singleflight"
)

const (
	cacheCleanupInterval = time.Minute
	whoisPort            = "43"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var templates = template.Must(template.ParseFS(
	templateFS,
	"templates/admin.html.tmpl",
	"templates/error.html.tmpl",
	"templates/stats.html.tmpl",
))

type cacheEntry struct {
	msg        *dns.Msg
	expiration time.Time
}

type LocalRecord struct {
	IP     net.IP
	TTL    uint32
	NoData bool
}

type Config struct {
	ListenAddrs      []string
	Upstreams        []string
	SpecialDomains   map[string]struct{}
	LocalA           map[string][]LocalRecord
	LocalAAAA        map[string][]LocalRecord
	WGGateway        string
	WGGatewayV4      string
	WGGatewayV6      string
	WGInterface      string
	RouteTable       int
	RouteIPv4        bool
	RouteIPv6        bool
	DefaultTTL       uint32
	LookupCIDR       bool
	ReplyBeforeRoute bool
}

type listenerSpec struct {
	Net  string
	Addr string
}

func (s listenerSpec) Key() string { return s.Net + "|" + s.Addr }

type RouteState string

const (
	StatePending RouteState = "pending"
	StateApplied RouteState = "applied"
	StateFailed  RouteState = "failed"
)

type routeCacheEntry struct {
	State     RouteState
	CIDR      string
	UpdatedAt time.Time
}

type RouteManager struct {
	app *App

	ipMu    sync.RWMutex
	ipCache map[string]routeCacheEntry

	cidrMu    sync.RWMutex
	cidrCache map[string]routeCacheEntry

	snapMu   sync.RWMutex
	snapshot []*net.IPNet

	lookupGroup singleflight.Group
	applyGroup  singleflight.Group

	queue chan string
	wg    sync.WaitGroup
}

type App struct {
	db *sql.DB

	cfg   *Config
	cfgMu sync.RWMutex

	cache   map[string]cacheEntry
	cacheMu sync.RWMutex

	cidrRe *regexp.Regexp

	servers map[string]*dns.Server
	srvMu   sync.Mutex

	adminAddr string
	startedAt time.Time

	routeMgr *RouteManager

	totalQueries       uint64
	cacheHits          uint64
	cacheMisses        uint64
	localAnswers       uint64
	forwardedOK        uint64
	servfailCount      uint64
	routeAdds          uint64
	routeAddErrors     uint64
	forwardErrors      uint64
	lookupCIDRAttempts uint64
	lookupCIDRFailed   uint64
}

type pageData struct {
	Config         *Config
	Settings       map[string]string
	ListenAddrs    []string
	Upstreams      []string
	SpecialDomains []string
	Records        []recordRow
	Message        string
}

type recordRow struct {
	ID      int64
	Name    string
	Type    string
	Value   string
	TTL     int
	Enabled bool
}

type statsData struct {
	Uptime           string
	StartedAt        string
	CacheEntries     int
	ActiveListeners  int
	ListenAddrs      int
	Upstreams        int
	SpecialDomains   int
	LocalADomains    int
	LocalAAAADomains int
	LookupCIDR       bool
	ReplyBeforeRoute bool
	RouteIPv4        bool
	RouteIPv6        bool
	RouteTable       int
	WGInterface      string
	WGGateway        string
	WGGatewayV4      string
	WGGatewayV6      string
	RouteSnapshot    int
	IPCacheEntries   int
	CIDRCacheEntries int

	TotalQueries       uint64
	CacheHits          uint64
	CacheMisses        uint64
	LocalAnswers       uint64
	ForwardedOK        uint64
	ServfailCount      uint64
	RouteAdds          uint64
	RouteAddErrors     uint64
	ForwardErrors      uint64
	LookupCIDRAttempts uint64
	LookupCIDRFailed   uint64
}

func main() {
	dbPath := flag.String("db", "/var/lib/dns-route/config.db", "path to sqlite config db")
	httpAddr := flag.String("http", "127.0.0.1:8080", "admin http listen addr")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatalf("init db: %v", err)
	}

	cfg, err := loadConfigFromDB(db)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	app := &App{
		db:        db,
		cfg:       cfg,
		cache:     make(map[string]cacheEntry),
		cidrRe:    regexp.MustCompile(`(?mi)^CIDR:\s*([0-9A-Fa-f:.]+/\d+)`),
		servers:   make(map[string]*dns.Server),
		adminAddr: *httpAddr,
		startedAt: time.Now(),
	}
	app.routeMgr = NewRouteManager(app, 8)
	if err := app.routeMgr.ReloadSnapshot(); err != nil {
		log.Printf("initial route snapshot reload failed: %v", err)
	}

	logConfig("CONFIG", cfg)
	rand.Seed(time.Now().UnixNano())
	app.startCacheCleanup()

	if err := app.reconcileListeners(cfg.ListenAddrs); err != nil {
		log.Fatalf("start listeners: %v", err)
	}

	app.startHTTP()
	select {}
}

func NewRouteManager(app *App, workers int) *RouteManager {
	rm := &RouteManager{
		app:       app,
		ipCache:   make(map[string]routeCacheEntry),
		cidrCache: make(map[string]routeCacheEntry),
		queue:     make(chan string, 1024),
	}
	for i := 0; i < workers; i++ {
		rm.wg.Add(1)
		go rm.worker()
	}
	return rm
}

func (rm *RouteManager) worker() {
	defer rm.wg.Done()
	for ip := range rm.queue {
		rm.processIP(ip)
	}
}

func (rm *RouteManager) EnsureIPs(ips []net.IP) {
	now := time.Now()
	unique := map[string]struct{}{}
	for _, ip := range ips {
		routeIP := normalizeRouteIP(ip)
		if routeIP == nil {
			continue
		}
		s := routeIP.String()
		if _, ok := unique[s]; ok {
			continue
		}
		unique[s] = struct{}{}

		defaultCIDR := defaultCIDRForIP(routeIP)
		if rm.ipCoveredBySnapshot(routeIP) {
			rm.markIPApplied(s, defaultCIDR, now)
			continue
		}

		rm.ipMu.Lock()
		ent, ok := rm.ipCache[s]
		if ok && (ent.State == StatePending || ent.State == StateApplied) {
			rm.ipMu.Unlock()
			continue
		}
		rm.ipCache[s] = routeCacheEntry{State: StatePending, CIDR: defaultCIDR, UpdatedAt: now}
		rm.ipMu.Unlock()

		select {
		case rm.queue <- s:
		default:
			go rm.processIP(s)
		}
	}
}

func (rm *RouteManager) processIP(ip string) {
	cfg := rm.app.getConfig()
	parsed := normalizeRouteIP(net.ParseIP(ip))
	if parsed == nil {
		return
	}
	ip = parsed.String()

	defaultCIDR := defaultCIDRForIP(parsed)
	if rm.ipCoveredBySnapshot(parsed) {
		rm.markIPApplied(ip, defaultCIDR, time.Now())
		return
	}

	cidr := defaultCIDR
	if cfg.LookupCIDR {
		atomic.AddUint64(&rm.app.lookupCIDRAttempts, 1)
		val, _, _ := rm.lookupGroup.Do(ip, func() (any, error) {
			if rm.ipCoveredBySnapshot(parsed) {
				return defaultCIDR, nil
			}
			c := rm.app.lookupCIDR(ip)
			if c == "" {
				atomic.AddUint64(&rm.app.lookupCIDRFailed, 1)
				return defaultCIDR, nil
			}
			return c, nil
		})
		cidr = val.(string)
	}

	rm.ipMu.Lock()
	rm.ipCache[ip] = routeCacheEntry{State: StatePending, CIDR: cidr, UpdatedAt: time.Now()}
	rm.ipMu.Unlock()

	if rm.cidrCoveredBySnapshot(cidr) {
		rm.markIPApplied(ip, cidr, time.Now())
		rm.markCIDRApplied(cidr, time.Now())
		return
	}

	rm.cidrMu.Lock()
	ent, ok := rm.cidrCache[cidr]
	if ok && (ent.State == StatePending || ent.State == StateApplied) {
		rm.cidrMu.Unlock()
		if ent.State == StateApplied {
			rm.markIPApplied(ip, cidr, time.Now())
		}
		return
	}
	rm.cidrCache[cidr] = routeCacheEntry{State: StatePending, CIDR: cidr, UpdatedAt: time.Now()}
	rm.cidrMu.Unlock()

	_, _, _ = rm.applyGroup.Do(cidr, func() (any, error) {
		if rm.cidrCoveredBySnapshot(cidr) {
			rm.markCIDRApplied(cidr, time.Now())
			rm.markIPApplied(ip, cidr, time.Now())
			return nil, nil
		}

		if err := rm.app.addRoute(cidr); err != nil {
			atomic.AddUint64(&rm.app.routeAddErrors, 1)
			// Принудительный refresh по ошибке.
			if reloadErr := rm.ReloadSnapshot(); reloadErr == nil && rm.cidrCoveredBySnapshot(cidr) {
				rm.markCIDRApplied(cidr, time.Now())
				rm.markIPApplied(ip, cidr, time.Now())
				return nil, nil
			}
			rm.markCIDRFailed(cidr, time.Now())
			rm.markIPFailed(ip, cidr, time.Now())
			return nil, err
		}

		atomic.AddUint64(&rm.app.routeAdds, 1)
		rm.addCIDRToSnapshot(cidr)
		rm.markCIDRApplied(cidr, time.Now())
		rm.markIPApplied(ip, cidr, time.Now())
		return nil, nil
	})
}

func (rm *RouteManager) markIPApplied(ip, cidr string, now time.Time) {
	rm.ipMu.Lock()
	rm.ipCache[ip] = routeCacheEntry{State: StateApplied, CIDR: cidr, UpdatedAt: now}
	rm.ipMu.Unlock()
}
func (rm *RouteManager) markIPFailed(ip, cidr string, now time.Time) {
	rm.ipMu.Lock()
	rm.ipCache[ip] = routeCacheEntry{State: StateFailed, CIDR: cidr, UpdatedAt: now}
	rm.ipMu.Unlock()
}
func (rm *RouteManager) markCIDRApplied(cidr string, now time.Time) {
	rm.cidrMu.Lock()
	rm.cidrCache[cidr] = routeCacheEntry{State: StateApplied, CIDR: cidr, UpdatedAt: now}
	rm.cidrMu.Unlock()
}
func (rm *RouteManager) markCIDRFailed(cidr string, now time.Time) {
	rm.cidrMu.Lock()
	rm.cidrCache[cidr] = routeCacheEntry{State: StateFailed, CIDR: cidr, UpdatedAt: now}
	rm.cidrMu.Unlock()
}

func (rm *RouteManager) routeTableForLookup() int {
	cfg := rm.app.getConfig()
	if cfg.RouteTable == 0 {
		return 254
	}
	return cfg.RouteTable
}

func (rm *RouteManager) ReloadSnapshot() error {
	filter := &netlink.Route{Table: rm.routeTableForLookup()}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("route list filtered: %w", err)
	}
	nets := make([]*net.IPNet, 0, len(routes))
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		dup := &net.IPNet{IP: append(net.IP(nil), r.Dst.IP...), Mask: append(net.IPMask(nil), r.Dst.Mask...)}
		nets = append(nets, dup)
	}
	rm.snapMu.Lock()
	rm.snapshot = nets
	rm.snapMu.Unlock()
	return nil
}

func (rm *RouteManager) addCIDRToSnapshot(cidr string) {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	rm.snapMu.Lock()
	defer rm.snapMu.Unlock()
	for _, n := range rm.snapshot {
		if n.String() == dst.String() {
			return
		}
	}
	dup := &net.IPNet{IP: append(net.IP(nil), dst.IP...), Mask: append(net.IPMask(nil), dst.Mask...)}
	rm.snapshot = append(rm.snapshot, dup)
}

func (rm *RouteManager) ipCoveredBySnapshot(ip net.IP) bool {
	rm.snapMu.RLock()
	defer rm.snapMu.RUnlock()
	for _, n := range rm.snapshot {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (rm *RouteManager) cidrCoveredBySnapshot(cidr string) bool {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	rm.snapMu.RLock()
	defer rm.snapMu.RUnlock()
	for _, n := range rm.snapshot {
		if n.String() == dst.String() || n.Contains(dst.IP) {
			return true
		}
	}
	return false
}

func normalizeRouteIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if v6 := ip.To16(); v6 != nil {
		return v6
	}
	return nil
}

func defaultCIDRForIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32"
	}
	return ip.String() + "/128"
}

func logConfig(prefix string, cfg *Config) {
	log.Printf(
		"%s: LISTEN=%v UPSTREAMS=%v WG_INTERFACE=%s WG_GATEWAY=%s WG_GATEWAY_V4=%s WG_GATEWAY_V6=%s ROUTE_TABLE=%d ROUTE_IPV4=%t ROUTE_IPV6=%t LOOKUP_CIDR=%t REPLY_BEFORE_ROUTE=%t SPECIAL_DOMAINS=%d LOCAL_A=%d LOCAL_AAAA=%d",
		prefix, cfg.ListenAddrs, cfg.Upstreams, cfg.WGInterface, cfg.WGGateway, cfg.WGGatewayV4, cfg.WGGatewayV6, cfg.RouteTable,
		cfg.RouteIPv4, cfg.RouteIPv6, cfg.LookupCIDR, cfg.ReplyBeforeRoute, len(cfg.SpecialDomains), len(cfg.LocalA), len(cfg.LocalAAAA),
	)
}

func renderError(w http.ResponseWriter, status int, err error) {
	w.WriteHeader(status)
	data := struct{ Error string }{Error: err.Error()}
	if tplErr := templates.ExecuteTemplate(w, "error.html.tmpl", data); tplErr != nil {
		http.Error(w, err.Error(), status)
	}
}

func loadConfigFromDB(db *sql.DB) (*Config, error) {
	cfg := &Config{
		SpecialDomains:   make(map[string]struct{}),
		LocalA:           make(map[string][]LocalRecord),
		LocalAAAA:        make(map[string][]LocalRecord),
		DefaultTTL:       60,
		RouteTable:       0,
		RouteIPv4:        true,
		RouteIPv6:        true,
		LookupCIDR:       true,
		ReplyBeforeRoute: false,
	}
	settings, err := readSettings(db)
	if err != nil {
		return nil, err
	}
	cfg.WGGateway = settings["wg_gateway"]
	cfg.WGGatewayV4 = settings["wg_gateway_v4"]
	cfg.WGGatewayV6 = settings["wg_gateway_v6"]
	cfg.WGInterface = settings["wg_interface"]
	if v := strings.TrimSpace(settings["route_table"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid route_table=%q: %w", v, err)
		}
		cfg.RouteTable = n
	}
	if v := strings.TrimSpace(settings["route_ipv4"]); v != "" {
		cfg.RouteIPv4 = isTrueString(v)
	}
	if v := strings.TrimSpace(settings["route_ipv6"]); v != "" {
		cfg.RouteIPv6 = isTrueString(v)
	}
	if v := strings.TrimSpace(settings["local_record_ttl"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid local_record_ttl=%q", v)
		}
		cfg.DefaultTTL = uint32(n)
	}
	if v := strings.TrimSpace(settings["lookup_cidr"]); v != "" {
		cfg.LookupCIDR = isTrueString(v)
	}
	if v := strings.TrimSpace(settings["reply_before_route"]); v != "" {
		cfg.ReplyBeforeRoute = isTrueString(v)
	}
	if err := readListenAddrs(db, cfg); err != nil {
		return nil, err
	}
	if err := readUpstreams(db, cfg); err != nil {
		return nil, err
	}
	if err := readSpecialDomains(db, cfg); err != nil {
		return nil, err
	}
	if err := readDNSRecords(db, cfg); err != nil {
		return nil, err
	}
	cfg.ListenAddrs = uniqueStrings(cfg.ListenAddrs)
	cfg.Upstreams = uniqueStrings(cfg.Upstreams)
	return cfg, nil
}

func isTrueString(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func initDB(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
		`CREATE TABLE IF NOT EXISTS listen_addrs (id INTEGER PRIMARY KEY AUTOINCREMENT, addr TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);`,
		`CREATE TABLE IF NOT EXISTS upstreams (id INTEGER PRIMARY KEY AUTOINCREMENT, addr TEXT NOT NULL UNIQUE, proto TEXT NOT NULL DEFAULT 'auto', enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 100);`,
		`CREATE TABLE IF NOT EXISTS special_domains (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);`,
		`CREATE TABLE IF NOT EXISTS dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1);`,
		`CREATE INDEX IF NOT EXISTS idx_dns_records_name_type ON dns_records(name, type, enabled);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func readSettings(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func readListenAddrs(db *sql.DB, cfg *Config) error {
	rows, err := db.Query(`SELECT addr FROM listen_addrs WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return err
		}
		if v = strings.TrimSpace(v); v != "" {
			cfg.ListenAddrs = append(cfg.ListenAddrs, v)
		}
	}
	return rows.Err()
}
func readUpstreams(db *sql.DB, cfg *Config) error {
	rows, err := db.Query(`SELECT addr FROM upstreams WHERE enabled = 1 ORDER BY priority, id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return err
		}
		if v = strings.TrimSpace(v); v != "" {
			cfg.Upstreams = append(cfg.Upstreams, v)
		}
	}
	return rows.Err()
}
func readSpecialDomains(db *sql.DB, cfg *Config) error {
	rows, err := db.Query(`SELECT domain FROM special_domains WHERE enabled = 1 ORDER BY domain`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return err
		}
		if v = normalizeName(v); v != "" {
			cfg.SpecialDomains[v] = struct{}{}
		}
	}
	return rows.Err()
}
func readDNSRecords(db *sql.DB, cfg *Config) error {
	rows, err := db.Query(`SELECT name, type, value, ttl FROM dns_records WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, typ, value string
		var ttl int
		if err := rows.Scan(&name, &typ, &value, &ttl); err != nil {
			return err
		}
		name = normalizeName(name)
		if name == "" {
			continue
		}
		value = strings.TrimSpace(value)
		recordTTL := cfg.DefaultTTL
		if ttl > 0 {
			recordTTL = uint32(ttl)
		}
		switch strings.ToUpper(strings.TrimSpace(typ)) {
		case "A":
			if value == "" {
				cfg.LocalA[name] = append(cfg.LocalA[name], LocalRecord{TTL: recordTTL, NoData: true})
				continue
			}
			ip := net.ParseIP(value)
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				cfg.LocalA[name] = append(cfg.LocalA[name], LocalRecord{IP: v4, TTL: recordTTL})
			}
		case "AAAA":
			if value == "" {
				cfg.LocalAAAA[name] = append(cfg.LocalAAAA[name], LocalRecord{TTL: recordTTL, NoData: true})
				continue
			}
			ip := net.ParseIP(value)
			if ip == nil {
				continue
			}
			if ip.To4() == nil {
				cfg.LocalAAAA[name] = append(cfg.LocalAAAA[name], LocalRecord{IP: ip, TTL: recordTTL})
			}
		}
	}
	return rows.Err()
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
func buildListenerSpecs(addrs []string) []listenerSpec {
	addrs = uniqueStrings(addrs)
	specs := make([]listenerSpec, 0, len(addrs)*2)
	for _, a := range addrs {
		specs = append(specs, listenerSpec{"udp", a}, listenerSpec{"tcp", a})
	}
	sort.Slice(specs, func(i, j int) bool {
		if specs[i].Net != specs[j].Net {
			return specs[i].Net < specs[j].Net
		}
		return specs[i].Addr < specs[j].Addr
	})
	return specs
}

func (a *App) getConfig() *Config    { a.cfgMu.RLock(); defer a.cfgMu.RUnlock(); return a.cfg }
func (a *App) setConfig(cfg *Config) { a.cfgMu.Lock(); a.cfg = cfg; a.cfgMu.Unlock() }

func (a *App) startCacheCleanup() {
	go func() {
		ticker := time.NewTicker(cacheCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			a.cacheMu.Lock()
			for k, e := range a.cache {
				if now.After(e.expiration) {
					delete(a.cache, k)
				}
			}
			a.cacheMu.Unlock()
		}
	}()
}

func (a *App) reloadConfig() error {
	cfg, err := loadConfigFromDB(a.db)
	if err != nil {
		return err
	}
	if err := a.reconcileListeners(cfg.ListenAddrs); err != nil {
		return err
	}
	a.setConfig(cfg)
	logConfig("CONFIG reloaded", cfg)
	return nil
}

func (a *App) reconcileListeners(listenAddrs []string) error {
	desiredSpecs := buildListenerSpecs(listenAddrs)
	desired := map[string]listenerSpec{}
	for _, s := range desiredSpecs {
		desired[s.Key()] = s
	}

	a.srvMu.Lock()
	current := make(map[string]*dns.Server, len(a.servers))
	for k, v := range a.servers {
		current[k] = v
	}
	a.srvMu.Unlock()

	started := map[string]*dns.Server{}
	for key, spec := range desired {
		if _, ok := current[key]; ok {
			continue
		}
		srv, err := a.newServer(spec)
		if err != nil {
			for _, s := range started {
				_ = s.Shutdown()
			}
			return err
		}
		started[key] = srv
		log.Printf("listener started: %s %s", spec.Net, spec.Addr)
	}

	var toStop []*dns.Server
	var stopDesc []string
	a.srvMu.Lock()
	for k, v := range started {
		a.servers[k] = v
	}
	for k, v := range a.servers {
		if _, ok := desired[k]; !ok {
			toStop = append(toStop, v)
			stopDesc = append(stopDesc, k)
			delete(a.servers, k)
		}
	}
	a.srvMu.Unlock()
	for i, srv := range toStop {
		if err := srv.Shutdown(); err != nil {
			log.Printf("listener shutdown error for %s: %v", stopDesc[i], err)
		}
	}
	return nil
}

func (a *App) newServer(spec listenerSpec) (*dns.Server, error) {
	handler := dns.HandlerFunc(a.handleDNS)
	switch spec.Net {
	case "udp":
		pc, err := net.ListenPacket("udp", spec.Addr)
		if err != nil {
			return nil, err
		}
		srv := &dns.Server{Net: "udp", PacketConn: pc, Handler: handler}
		go a.serveLoop(srv, spec)
		return srv, nil
	case "tcp":
		ln, err := net.Listen("tcp", spec.Addr)
		if err != nil {
			return nil, err
		}
		srv := &dns.Server{Net: "tcp", Listener: ln, Handler: handler}
		go a.serveLoop(srv, spec)
		return srv, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", spec.Net)
	}
}
func (a *App) serveLoop(srv *dns.Server, spec listenerSpec) {
	err := srv.ActivateAndServe()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("listener serve error %s %s: %v", spec.Net, spec.Addr, err)
	}
}

func (a *App) startHTTP() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleAdmin)
	mux.HandleFunc("/reload", a.handleReload)
	mux.HandleFunc("/routes/reload", a.handleRoutesReload)
	mux.HandleFunc("/stats", a.handleStats)
	mux.HandleFunc("/metrics", a.handleMetrics)
	mux.HandleFunc("/settings/save", a.handleSettingsSave)
	mux.HandleFunc("/listen/add", a.handleListenAdd)
	mux.HandleFunc("/listen/delete", a.handleListenDelete)
	mux.HandleFunc("/upstream/add", a.handleUpstreamAdd)
	mux.HandleFunc("/upstream/delete", a.handleUpstreamDelete)
	mux.HandleFunc("/special/add", a.handleSpecialAdd)
	mux.HandleFunc("/special/delete", a.handleSpecialDelete)
	mux.HandleFunc("/record/add", a.handleRecordAdd)
	mux.HandleFunc("/record/delete", a.handleRecordDelete)
	go func() {
		log.Printf("admin http listening on %s", a.adminAddr)
		if err := http.ListenAndServe(a.adminAddr, mux); err != nil {
			log.Fatalf("admin http failed: %v", err)
		}
	}()
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	settings, err := readSettings(a.db)
	if err != nil {
		renderError(w, 500, err)
		return
	}
	listenAddrs, err := a.listSimple(`SELECT addr FROM listen_addrs WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		renderError(w, 500, err)
		return
	}
	upstreams, err := a.listSimple(`SELECT addr FROM upstreams WHERE enabled = 1 ORDER BY priority, id`)
	if err != nil {
		renderError(w, 500, err)
		return
	}
	specials, err := a.listSimple(`SELECT domain FROM special_domains WHERE enabled = 1 ORDER BY domain`)
	if err != nil {
		renderError(w, 500, err)
		return
	}
	records, err := a.listRecords()
	if err != nil {
		renderError(w, 500, err)
		return
	}
	data := pageData{Config: a.getConfig(), Settings: settings, ListenAddrs: listenAddrs, Upstreams: upstreams, SpecialDomains: specials, Records: records, Message: a.adminAddr}
	if err := templates.ExecuteTemplate(w, "admin.html.tmpl", data); err != nil {
		renderError(w, 500, err)
	}
}
func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/stats" {
		http.NotFound(w, r)
		return
	}
	if err := templates.ExecuteTemplate(w, "stats.html.tmpl", a.statsSnapshot()); err != nil {
		renderError(w, 500, err)
	}
}
func (a *App) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) handleRoutesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	if err := a.routeMgr.ReloadSnapshot(); err != nil {
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	lookupCIDR := "0"
	if r.FormValue("lookup_cidr") != "" {
		lookupCIDR = "1"
	}
	replyBeforeRoute := "0"
	if r.FormValue("reply_before_route") != "" {
		replyBeforeRoute = "1"
	}
	routeIPv4 := "0"
	if r.FormValue("route_ipv4") != "" {
		routeIPv4 = "1"
	}
	routeIPv6 := "0"
	if r.FormValue("route_ipv6") != "" {
		routeIPv6 = "1"
	}
	settings := map[string]string{
		"wg_interface":       strings.TrimSpace(r.FormValue("wg_interface")),
		"wg_gateway":         strings.TrimSpace(r.FormValue("wg_gateway")),
		"wg_gateway_v4":      strings.TrimSpace(r.FormValue("wg_gateway_v4")),
		"wg_gateway_v6":      strings.TrimSpace(r.FormValue("wg_gateway_v6")),
		"route_table":        strings.TrimSpace(r.FormValue("route_table")),
		"route_ipv4":         routeIPv4,
		"route_ipv6":         routeIPv6,
		"local_record_ttl":   strings.TrimSpace(r.FormValue("local_record_ttl")),
		"lookup_cidr":        lookupCIDR,
		"reply_before_route": replyBeforeRoute,
	}
	for k, v := range settings {
		if _, err := a.db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			renderError(w, 500, err)
			return
		}
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleListenAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	addr := strings.TrimSpace(r.FormValue("addr"))
	if addr == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, err := a.db.Exec(`INSERT OR IGNORE INTO listen_addrs(addr, enabled) VALUES(?, 1)`, addr); err != nil {
		renderError(w, 500, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		_, _ = a.db.Exec(`DELETE FROM listen_addrs WHERE addr = ?`, addr)
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) handleListenDelete(w http.ResponseWriter, r *http.Request) {
	a.handleSimpleDelete(w, r, `DELETE FROM listen_addrs WHERE addr = ?`, strings.TrimSpace(r.FormValue("addr")))
}
func (a *App) handleUpstreamAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	addr := strings.TrimSpace(r.FormValue("addr"))
	if addr == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, err := a.db.Exec(`INSERT OR IGNORE INTO upstreams(addr, enabled, priority) VALUES(?, 1, 100)`, addr); err != nil {
		renderError(w, 500, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		_, _ = a.db.Exec(`DELETE FROM upstreams WHERE addr = ?`, addr)
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) handleUpstreamDelete(w http.ResponseWriter, r *http.Request) {
	a.handleSimpleDelete(w, r, `DELETE FROM upstreams WHERE addr = ?`, strings.TrimSpace(r.FormValue("addr")))
}
func (a *App) handleSpecialAdd(w http.ResponseWriter, r *http.Request) {
	a.handleSimpleInsert(w, r, `INSERT OR IGNORE INTO special_domains(domain, enabled) VALUES(?, 1)`, normalizeName(r.FormValue("domain")))
}
func (a *App) handleSpecialDelete(w http.ResponseWriter, r *http.Request) {
	a.handleSimpleDelete(w, r, `DELETE FROM special_domains WHERE domain = ?`, normalizeName(r.FormValue("domain")))
}

func (a *App) handleRecordAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	name := normalizeName(r.FormValue("name"))
	rtype := strings.ToUpper(strings.TrimSpace(r.FormValue("type")))
	value := strings.TrimSpace(r.FormValue("value"))
	ttlStr := strings.TrimSpace(r.FormValue("ttl"))
	if name == "" || (rtype != "A" && rtype != "AAAA") {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if value != "" {
		ip := net.ParseIP(value)
		if ip == nil {
			renderError(w, 400, fmt.Errorf("invalid ip"))
			return
		}
		if rtype == "A" && ip.To4() == nil {
			renderError(w, 400, fmt.Errorf("A requires IPv4"))
			return
		}
		if rtype == "AAAA" && ip.To4() != nil {
			renderError(w, 400, fmt.Errorf("AAAA requires IPv6"))
			return
		}
	}
	ttl := 0
	if ttlStr != "" {
		n, err := strconv.Atoi(ttlStr)
		if err != nil || n < 0 {
			renderError(w, 400, fmt.Errorf("invalid ttl"))
			return
		}
		ttl = n
	}
	if _, err := a.db.Exec(`INSERT INTO dns_records(name, type, value, ttl, enabled) VALUES(?, ?, ?, ?, 1)`, name, rtype, value, ttl); err != nil {
		renderError(w, 500, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) handleRecordDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil {
		renderError(w, 400, fmt.Errorf("invalid id"))
		return
	}
	if _, err := a.db.Exec(`DELETE FROM dns_records WHERE id = ?`, id); err != nil {
		renderError(w, 500, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) handleSimpleInsert(w http.ResponseWriter, r *http.Request, query, value string) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	if value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, err := a.db.Exec(query, value); err != nil {
		renderError(w, 500, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) handleSimpleDelete(w http.ResponseWriter, r *http.Request, query, value string) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	if value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, err := a.db.Exec(query, value); err != nil {
		renderError(w, 500, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, 500, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) listSimple(query string) ([]string, error) {
	rows, err := a.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (a *App) listRecords() ([]recordRow, error) {
	rows, err := a.db.Query(`SELECT id, name, type, value, ttl, enabled FROM dns_records ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []recordRow
	for rows.Next() {
		var rr recordRow
		var enabled int
		if err := rows.Scan(&rr.ID, &rr.Name, &rr.Type, &rr.Value, &rr.TTL, &enabled); err != nil {
			return nil, err
		}
		rr.Enabled = enabled != 0
		out = append(out, rr)
	}
	return out, rows.Err()
}

func (a *App) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	atomic.AddUint64(&a.totalQueries, 1)
	if len(req.Question) == 0 {
		atomic.AddUint64(&a.servfailCount, 1)
		respondSERVFAIL(w, req)
		return
	}

	q := req.Question[0]
	name := normalizeName(q.Name)
	key := name + ":" + dns.TypeToString[q.Qtype]

	if resp := a.localResponse(req, q); resp != nil {
		atomic.AddUint64(&a.localAnswers, 1)
		_ = w.WriteMsg(resp)
		return
	}

	a.cacheMu.RLock()
	if entry, ok := a.cache[key]; ok && time.Now().Before(entry.expiration) {
		a.cacheMu.RUnlock()
		atomic.AddUint64(&a.cacheHits, 1)
		cached := entry.msg.Copy()
		cached.Id = req.Id
		cfg := a.getConfig()
		ips := a.routeIPsFromAnswers(name, q.Qtype, cached.Answer, cfg)
		if cfg.ReplyBeforeRoute {
			_ = w.WriteMsg(cached)
			if len(ips) > 0 {
				a.routeMgr.EnsureIPs(ips)
			}
			return
		}
		if len(ips) > 0 {
			a.routeMgr.EnsureIPs(ips)
		}
		_ = w.WriteMsg(cached)
		return
	}
	a.cacheMu.RUnlock()
	atomic.AddUint64(&a.cacheMisses, 1)

	resp, err := a.forwardDNS(req)
	if err != nil {
		atomic.AddUint64(&a.forwardErrors, 1)
		atomic.AddUint64(&a.servfailCount, 1)
		respondSERVFAIL(w, req)
		return
	}
	resp.Id = req.Id

	if len(resp.Answer) > 0 {
		minTTL := resp.Answer[0].Header().Ttl
		for _, rr := range resp.Answer[1:] {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		a.cacheMu.Lock()
		a.cache[key] = cacheEntry{msg: resp.Copy(), expiration: time.Now().Add(time.Duration(minTTL) * time.Second)}
		a.cacheMu.Unlock()
	}

	cfg := a.getConfig()
	ips := a.routeIPsFromAnswers(name, q.Qtype, resp.Answer, cfg)

	if cfg.ReplyBeforeRoute {
		_ = w.WriteMsg(resp)
		atomic.AddUint64(&a.forwardedOK, 1)
		if len(ips) > 0 {
			a.routeMgr.EnsureIPs(ips)
		}
		return
	}

	if len(ips) > 0 {
		a.routeMgr.EnsureIPs(ips)
	}
	_ = w.WriteMsg(resp)
	atomic.AddUint64(&a.forwardedOK, 1)
}

func (a *App) localResponse(req *dns.Msg, q dns.Question) *dns.Msg {
	name := normalizeName(q.Name)
	records := a.findLocalRecords(name, q.Qtype)
	if len(records) == 0 {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	fqdn := dns.Fqdn(name)
	for _, rec := range records {
		if rec.NoData {
			return resp
		}
	}
	for _, rec := range records {
		switch q.Qtype {
		case dns.TypeA:
			if rec.IP == nil {
				continue
			}
			if v4 := rec.IP.To4(); v4 != nil {
				resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec.TTL}, A: v4})
			}
		case dns.TypeAAAA:
			if rec.IP != nil && rec.IP.To4() == nil {
				resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rec.TTL}, AAAA: rec.IP})
			}
		}
	}
	return resp
}
func (a *App) findLocalRecords(name string, qtype uint16) []LocalRecord {
	cfg := a.getConfig()
	var m map[string][]LocalRecord
	switch qtype {
	case dns.TypeA:
		m = cfg.LocalA
	case dns.TypeAAAA:
		m = cfg.LocalAAAA
	default:
		return nil
	}
	if recs, ok := m[name]; ok && len(recs) > 0 {
		return recs
	}
	parts := strings.Split(name, ".")
	for i := 1; i < len(parts); i++ {
		wc := "*." + strings.Join(parts[i:], ".")
		if recs, ok := m[wc]; ok && len(recs) > 0 {
			return recs
		}
	}
	return nil
}

func (a *App) forwardDNS(req *dns.Msg) (*dns.Msg, error) {
	cfg := a.getConfig()
	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}
	var lastErr error
	for _, upstream := range a.shuffledUpstreams() {
		var resp *dns.Msg
		var err error
		if strings.HasPrefix(upstream, "https://") {
			wire, errPack := req.Pack()
			if errPack != nil {
				lastErr = errPack
				continue
			}
			httpReq, errReq := http.NewRequest("POST", upstream, bytes.NewReader(wire))
			if errReq != nil {
				lastErr = errReq
				continue
			}
			httpReq.Header.Set("Content-Type", "application/dns-message")
			httpReq.Header.Set("Accept", "application/dns-message")
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			httpResp, errDoH := client.Do(httpReq)
			if errDoH != nil {
				lastErr = errDoH
				continue
			}
			body, errRead := io.ReadAll(httpResp.Body)
			_ = httpResp.Body.Close()
			if errRead != nil {
				lastErr = errRead
				continue
			}
			if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
				lastErr = fmt.Errorf("unexpected HTTP status %s", httpResp.Status)
				continue
			}
			resp = new(dns.Msg)
			if err = resp.Unpack(body); err != nil {
				lastErr = err
				continue
			}
		} else {
			client := &dns.Client{Net: "tcp-tls", Timeout: 5 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
			resp, _, err = client.Exchange(req, upstream)
			if err != nil {
				lastErr = err
				continue
			}
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstreams configured")
	}
	return nil, lastErr
}
func (a *App) shuffledUpstreams() []string {
	cfg := a.getConfig()
	res := append([]string(nil), cfg.Upstreams...)
	rand.Shuffle(len(res), func(i, j int) { res[i], res[j] = res[j], res[i] })
	return res
}
func (a *App) routeIPsFromAnswers(name string, qtype uint16, answers []dns.RR, cfg *Config) []net.IP {
	if !a.routeEnabledForQuestion(qtype, cfg) || !a.isSpecial(name) {
		return nil
	}
	seen := map[string]struct{}{}
	var ips []net.IP
	for _, rr := range answers {
		var ip net.IP
		switch qtype {
		case dns.TypeA:
			if aRec, ok := rr.(*dns.A); ok && aRec.A != nil {
				ip = aRec.A.To4()
			}
		case dns.TypeAAAA:
			if aaaaRec, ok := rr.(*dns.AAAA); ok && aaaaRec.AAAA != nil && aaaaRec.AAAA.To4() == nil {
				ip = aaaaRec.AAAA.To16()
			}
		}
		if ip == nil {
			continue
		}
		s := ip.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		ips = append(ips, ip)
	}
	return ips
}

func (a *App) routeEnabledForQuestion(qtype uint16, cfg *Config) bool {
	switch qtype {
	case dns.TypeA:
		return cfg.RouteIPv4
	case dns.TypeAAAA:
		return cfg.RouteIPv6
	default:
		return false
	}
}

func (a *App) isSpecial(name string) bool {
	cfg := a.getConfig()
	for d := range cfg.SpecialDomains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func (a *App) lookupCIDR(ip string) string {
	data, err := whoisQuery("whois.iana.org:"+whoisPort, ip)
	if err != nil {
		return ""
	}
	refer := parseField(data, `(?mi)^refer:\s*(\S+)`)
	combined := data
	if refer != "" {
		if data2, err2 := whoisQuery(refer+":"+whoisPort, ip); err2 == nil {
			combined = append(combined, data2...)
		}
	}
	matches := a.cidrRe.FindAllSubmatch(combined, -1)
	var bestNet *net.IPNet
	bestOnes := -1
	for _, m := range matches {
		_, netw, err := net.ParseCIDR(string(m[1]))
		if err != nil {
			continue
		}
		ones, bits := netw.Mask.Size()
		if bits == 0 {
			continue
		}
		if ones > bestOnes {
			bestOnes, bestNet = ones, netw
		}
	}
	if bestNet != nil {
		return bestNet.String()
	}
	return ""
}

func whoisQuery(server, query string) ([]byte, error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	_, err = io.Copy(&buf, bufio.NewReader(conn))
	return buf.Bytes(), err
}
func parseField(data []byte, pattern string) string {
	re := regexp.MustCompile(pattern)
	for _, line := range strings.Split(string(data), "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}
func respondSERVFAIL(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}

func (a *App) addRoute(cidr string) error {
	cfg := a.getConfig()
	if cfg.WGInterface == "" {
		return fmt.Errorf("wg_interface is empty")
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(cfg.WGInterface)
	if err != nil {
		return err
	}
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Table: cfg.RouteTable}
	if gw, ok, err := routeGatewayForCIDR(cfg, dst); err != nil {
		return err
	} else if ok {
		route.Gw = gw
	}
	return netlink.RouteReplace(&route)
}

func routeGatewayForCIDR(cfg *Config, dst *net.IPNet) (net.IP, bool, error) {
	if dst.IP.To4() != nil {
		gwValue := strings.TrimSpace(cfg.WGGatewayV4)
		if gwValue == "" {
			gwValue = strings.TrimSpace(cfg.WGGateway)
		}
		if gwValue == "" {
			return nil, false, fmt.Errorf("wg_gateway_v4 or legacy wg_gateway is empty")
		}
		gw := net.ParseIP(gwValue)
		if gw == nil || gw.To4() == nil {
			return nil, false, fmt.Errorf("gateway %q is not an IPv4 address for IPv4 route %s", gwValue, dst.String())
		}
		return gw.To4(), true, nil
	}

	gwValue := strings.TrimSpace(cfg.WGGatewayV6)
	if gwValue == "" {
		gw := net.ParseIP(strings.TrimSpace(cfg.WGGateway))
		if gw != nil && gw.To4() == nil {
			gwValue = strings.TrimSpace(cfg.WGGateway)
		}
	}
	if gwValue == "" {
		return nil, false, nil
	}
	gw := net.ParseIP(gwValue)
	if gw == nil || gw.To4() != nil {
		return nil, false, fmt.Errorf("gateway %q is not an IPv6 address for IPv6 route %s", gwValue, dst.String())
	}
	return gw.To16(), true, nil
}

func (a *App) statsSnapshot() statsData {
	cfg := a.getConfig()
	a.cacheMu.RLock()
	cacheEntries := len(a.cache)
	a.cacheMu.RUnlock()
	a.srvMu.Lock()
	activeListeners := len(a.servers)
	a.srvMu.Unlock()
	a.routeMgr.snapMu.RLock()
	routeSnapshot := len(a.routeMgr.snapshot)
	a.routeMgr.snapMu.RUnlock()
	a.routeMgr.ipMu.RLock()
	ipEntries := len(a.routeMgr.ipCache)
	a.routeMgr.ipMu.RUnlock()
	a.routeMgr.cidrMu.RLock()
	cidrEntries := len(a.routeMgr.cidrCache)
	a.routeMgr.cidrMu.RUnlock()
	return statsData{
		Uptime:          time.Since(a.startedAt).Truncate(time.Second).String(),
		StartedAt:       a.startedAt.Format(time.RFC3339),
		CacheEntries:    cacheEntries,
		ActiveListeners: activeListeners,
		ListenAddrs:     len(cfg.ListenAddrs), Upstreams: len(cfg.Upstreams), SpecialDomains: len(cfg.SpecialDomains),
		LocalADomains: len(cfg.LocalA), LocalAAAADomains: len(cfg.LocalAAAA), LookupCIDR: cfg.LookupCIDR,
		ReplyBeforeRoute: cfg.ReplyBeforeRoute, RouteIPv4: cfg.RouteIPv4, RouteIPv6: cfg.RouteIPv6, RouteTable: cfg.RouteTable, WGInterface: cfg.WGInterface, WGGateway: cfg.WGGateway, WGGatewayV4: cfg.WGGatewayV4, WGGatewayV6: cfg.WGGatewayV6,
		RouteSnapshot: routeSnapshot, IPCacheEntries: ipEntries, CIDRCacheEntries: cidrEntries,
		TotalQueries: atomic.LoadUint64(&a.totalQueries), CacheHits: atomic.LoadUint64(&a.cacheHits), CacheMisses: atomic.LoadUint64(&a.cacheMisses),
		LocalAnswers: atomic.LoadUint64(&a.localAnswers), ForwardedOK: atomic.LoadUint64(&a.forwardedOK), ServfailCount: atomic.LoadUint64(&a.servfailCount),
		RouteAdds: atomic.LoadUint64(&a.routeAdds), RouteAddErrors: atomic.LoadUint64(&a.routeAddErrors), ForwardErrors: atomic.LoadUint64(&a.forwardErrors),
		LookupCIDRAttempts: atomic.LoadUint64(&a.lookupCIDRAttempts), LookupCIDRFailed: atomic.LoadUint64(&a.lookupCIDRFailed),
	}
}

func (a *App) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	s := a.statsSnapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	gauge := func(name string, v any, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, v)
	}
	counter := func(name string, v uint64, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	gauge("dns_route_uptime_seconds", int64(time.Since(a.startedAt).Seconds()), "process uptime in seconds")
	gauge("dns_route_cache_entries", s.CacheEntries, "number of cache entries")
	gauge("dns_route_active_listeners", s.ActiveListeners, "number of active listeners")
	gauge("dns_route_listen_addrs", s.ListenAddrs, "number of configured listen addresses")
	gauge("dns_route_upstreams", s.Upstreams, "number of configured upstreams")
	gauge("dns_route_special_domains", s.SpecialDomains, "number of special domains")
	gauge("dns_route_local_a_domains", s.LocalADomains, "number of local A domains")
	gauge("dns_route_local_aaaa_domains", s.LocalAAAADomains, "number of local AAAA domains")
	gauge("dns_route_lookup_cidr_enabled", boolToInt(s.LookupCIDR), "lookupCIDR enabled")
	gauge("dns_route_reply_before_route_enabled", boolToInt(s.ReplyBeforeRoute), "reply before route enabled")
	gauge("dns_route_route_ipv4_enabled", boolToInt(s.RouteIPv4), "IPv4 route programming enabled")
	gauge("dns_route_route_ipv6_enabled", boolToInt(s.RouteIPv6), "IPv6 route programming enabled")
	gauge("dns_route_route_table", s.RouteTable, "configured route table")
	gauge("dns_route_route_snapshot_entries", s.RouteSnapshot, "route snapshot entries")
	gauge("dns_route_route_ip_cache_entries", s.IPCacheEntries, "route manager IP cache entries")
	gauge("dns_route_route_cidr_cache_entries", s.CIDRCacheEntries, "route manager CIDR cache entries")
	counter("dns_route_queries_total", s.TotalQueries, "total DNS queries")
	counter("dns_route_cache_hits_total", s.CacheHits, "cache hits")
	counter("dns_route_cache_misses_total", s.CacheMisses, "cache misses")
	counter("dns_route_local_answers_total", s.LocalAnswers, "local answers")
	counter("dns_route_forwarded_ok_total", s.ForwardedOK, "successful forwarded answers")
	counter("dns_route_servfail_total", s.ServfailCount, "servfail responses")
	counter("dns_route_route_add_total", s.RouteAdds, "successful route additions")
	counter("dns_route_route_add_errors_total", s.RouteAddErrors, "route add errors")
	counter("dns_route_forward_errors_total", s.ForwardErrors, "forward errors")
	fmt.Fprintf(w, "# HELP dns_route_lookup_cidr_total lookupCIDR counters\n# TYPE dns_route_lookup_cidr_total counter\n")
	fmt.Fprintf(w, "dns_route_lookup_cidr_total{result=\"attempts\"} %d\n", s.LookupCIDRAttempts)
	fmt.Fprintf(w, "dns_route_lookup_cidr_total{result=\"failed\"} %d\n", s.LookupCIDRFailed)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
