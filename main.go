package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/singleflight"
)

const (
	cacheCleanupInterval       = time.Minute
	listenerRetryInterval      = 3 * time.Second
	mainRouteTable             = 254
	routeErrorHistoryLen       = 100
	upstreamFailureThreshold   = 2
	upstreamCircuitBaseBackoff = 30 * time.Second
	upstreamCircuitMaxBackoff  = 5 * time.Minute
	ipv6FreeBind               = 78
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

type upstreamCircuitState string

const (
	upstreamCircuitClosed   upstreamCircuitState = "closed"
	upstreamCircuitOpen     upstreamCircuitState = "open"
	upstreamCircuitHalfOpen upstreamCircuitState = "half_open"
)

type upstreamCircuit struct {
	RawAddr         string
	ConfiguredProto string
	Proto           string

	State               upstreamCircuitState
	ConsecutiveFailures uint64
	BackoffLevel        uint
	OpenUntil           time.Time
	ProbeInFlight       bool
	Generation          uint64

	Successes      uint64
	Failures       uint64
	DNSFailures    uint64
	Skipped        uint64
	OpenEvents     uint64
	Recoveries     uint64
	HalfOpenProbes uint64

	LastSuccess time.Time
	LastFailure time.Time
	LastError   string
}

type upstreamCircuitAttempt struct {
	Key        string
	Generation uint64
	HalfOpen   bool
}

type upstreamCircuitSnapshot struct {
	RawAddr             string
	ConfiguredProto     string
	Proto               string
	State               upstreamCircuitState
	ConsecutiveFailures uint64
	OpenUntil           time.Time
	Successes           uint64
	Failures            uint64
	DNSFailures         uint64
	Skipped             uint64
	OpenEvents          uint64
	Recoveries          uint64
	HalfOpenProbes      uint64
	LastSuccess         time.Time
	LastFailure         time.Time
	LastError           string
}

type LocalRecord struct {
	IP     net.IP
	TTL    uint32
	NoData bool
}

type upstreamTarget struct {
	Addr  string
	Proto string
}

type ForwardZoneUpstream struct {
	ID       int64
	Addr     string
	Proto    string
	Priority int
}

type ForwardZone struct {
	ID        int64
	Domain    string
	Upstreams []ForwardZoneUpstream
}

type forwardPolicy struct {
	Key       string
	Domain    string
	CacheKey  string
	Upstreams []upstreamTarget
}

type Config struct {
	ListenAddrs      []string
	ListenerFreeBind bool
	Upstreams        []string
	UpstreamProto    map[string]string
	ForwardZones     []ForwardZone
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

type managedListener struct {
	Server    *dns.Server
	Spec      listenerSpec
	FreeBind  bool
	StartedAt time.Time
}

type pendingListener struct {
	Spec        listenerSpec
	FreeBind    bool
	Attempts    uint64
	LastAttempt time.Time
	LastError   string
}

type listenerView struct {
	Net         string
	Addr        string
	State       string
	FreeBind    bool
	Attempts    uint64
	StartedAt   string
	LastAttempt string
	LastError   string
}

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

// conntrackIPFilter matches every conntrack flow involving IP in either
// direction. This also catches NATed flows where the remote address may be
// present only in the reply tuple.
type conntrackIPFilter struct {
	ip net.IP
}

func (f conntrackIPFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if flow == nil || f.ip == nil {
		return false
	}
	return flow.Forward.SrcIP.Equal(f.ip) ||
		flow.Forward.DstIP.Equal(f.ip) ||
		flow.Reverse.SrcIP.Equal(f.ip) ||
		flow.Reverse.DstIP.Equal(f.ip)
}

type routeErrorDiagnostic struct {
	Time                    string   `json:"time"`
	IP                      string   `json:"ip"`
	CIDR                    string   `json:"cidr"`
	Family                  string   `json:"family"`
	Table                   int      `json:"table"`
	Interface               string   `json:"interface"`
	LinkIndex               int      `json:"link_index,omitempty"`
	LinkType                string   `json:"link_type,omitempty"`
	LinkFlags               string   `json:"link_flags,omitempty"`
	LinkOperState           string   `json:"link_oper_state,omitempty"`
	Gateway                 string   `json:"gateway,omitempty"`
	Error                   string   `json:"error"`
	ErrorType               string   `json:"error_type"`
	Errno                   int      `json:"errno,omitempty"`
	ErrnoText               string   `json:"errno_text,omitempty"`
	InterfaceAddresses      []string `json:"interface_addresses,omitempty"`
	DestinationRoutes       []string `json:"destination_routes,omitempty"`
	GatewayRoutes           []string `json:"gateway_routes,omitempty"`
	RouteListError          string   `json:"route_list_error,omitempty"`
	LinkLookupError         string   `json:"link_lookup_error,omitempty"`
	AddressListError        string   `json:"address_list_error,omitempty"`
	SnapshotReloadError     string   `json:"snapshot_reload_error,omitempty"`
	RoutePresentAfterReload bool     `json:"route_present_after_reload"`
}

type RouteManager struct {
	app *App

	ipMu    sync.RWMutex
	ipCache map[string]routeCacheEntry

	cidrMu    sync.RWMutex
	cidrCache map[string]routeCacheEntry

	snapMu   sync.RWMutex
	snapshot []netip.Prefix

	lookupGroup  singleflight.Group
	applyGroup   singleflight.Group
	processGroup singleflight.Group

	resetMu         sync.Mutex
	resetAfterApply map[string]struct{}

	queue chan string
	wg    sync.WaitGroup
}

type App struct {
	db *sql.DB

	cfg   *Config
	cfgMu sync.RWMutex

	cache   map[string]cacheEntry
	cacheMu sync.RWMutex

	dohClient *http.Client

	upstreamMu       sync.Mutex
	upstreamCircuits map[string]*upstreamCircuit

	forwardLogMu           sync.Mutex
	lastForwardErrorLog    time.Time
	forwardErrorSuppressed uint64

	forwardPolicyMu    sync.Mutex
	forwardPolicyStats map[string]*forwardPolicyCounter

	servers             map[string]*managedListener
	pendingListeners    map[string]*pendingListener
	srvMu               sync.Mutex
	listenerReconcileMu sync.Mutex

	adminAddr string
	startedAt time.Time

	routeMgr *RouteManager

	routeErrMu    sync.Mutex
	routeErrorLog []routeErrorDiagnostic

	totalQueries           uint64
	cacheHits              uint64
	cacheMisses            uint64
	localAnswers           uint64
	forwardedOK            uint64
	servfailCount          uint64
	routeAdds              uint64
	routeAddErrors         uint64
	forwardErrors          uint64
	lookupCIDRAttempts     uint64
	lookupCIDRFailed       uint64
	routeQueueDrops        uint64
	conntrackResetAttempts uint64
	conntrackResetDeleted  uint64
	conntrackResetErrors   uint64
	listenerBindAttempts   uint64
	listenerBindErrors     uint64
	listenerStarts         uint64
	listenerRecoveries     uint64
}

type upstreamView struct {
	Addr                string
	ConfiguredProto     string
	Scopes              string
	Proto               string
	Endpoint            string
	State               string
	ConsecutiveFailures uint64
	OpenRemaining       string
	Successes           uint64
	Failures            uint64
	DNSFailures         uint64
	Skipped             uint64
	OpenEvents          uint64
	Recoveries          uint64
	HalfOpenProbes      uint64
	LastSuccess         string
	LastFailure         string
	LastError           string
}

type forwardZoneUpstreamView struct {
	ID   int64
	View upstreamView
}

type forwardZoneView struct {
	ID        int64
	Domain    string
	Pattern   string
	Upstreams []forwardZoneUpstreamView
}

type forwardPolicyCounter struct {
	Selected    uint64
	Success     uint64
	DNSFailures uint64
	Errors      uint64
}

type forwardPolicyView struct {
	Policy      string
	Selected    uint64
	Success     uint64
	DNSFailures uint64
	Errors      uint64
}

type pageData struct {
	Config         *Config
	Settings       map[string]string
	ListenAddrs    []string
	ListenerStates []listenerView
	Upstreams      []upstreamView
	ForwardZones   []forwardZoneView
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
	PendingListeners int
	ListenAddrs      int
	Upstreams        int
	ForwardZones     int
	ForwardUpstreams int
	SpecialDomains   int
	LocalADomains    int
	LocalAAAADomains int
	LookupCIDR       bool
	ReplyBeforeRoute bool
	ListenerFreeBind bool
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

	TotalQueries           uint64
	CacheHits              uint64
	CacheMisses            uint64
	LocalAnswers           uint64
	ForwardedOK            uint64
	ServfailCount          uint64
	RouteAdds              uint64
	RouteAddErrors         uint64
	ForwardErrors          uint64
	LookupCIDRAttempts     uint64
	LookupCIDRFailed       uint64
	RouteQueueDrops        uint64
	ConntrackResetAttempts uint64
	ConntrackResetDeleted  uint64
	ConntrackResetErrors   uint64
	ListenerBindAttempts   uint64
	ListenerBindErrors     uint64
	ListenerStarts         uint64
	ListenerRecoveries     uint64

	UpstreamCircuits []upstreamView
	ForwardPolicies  []forwardPolicyView
	ListenerStates   []listenerView
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
		db:                 db,
		cfg:                cfg,
		cache:              make(map[string]cacheEntry),
		dohClient:          newDoHClient(),
		upstreamCircuits:   make(map[string]*upstreamCircuit),
		forwardPolicyStats: make(map[string]*forwardPolicyCounter),
		servers:            make(map[string]*managedListener),
		pendingListeners:   make(map[string]*pendingListener),
		adminAddr:          *httpAddr,
		startedAt:          time.Now(),
	}
	app.syncUpstreamCircuits(cfg)
	app.routeMgr = NewRouteManager(app, 8)
	if err := app.routeMgr.ReloadSnapshot(); err != nil {
		log.Printf("initial route snapshot reload failed: %v", err)
	}

	logConfig("CONFIG", cfg)
	rand.Seed(time.Now().UnixNano())
	app.startCacheCleanup()
	if err := app.validateTemplates(); err != nil {
		log.Fatalf("validate templates: %v", err)
	}
	app.startHTTP()
	app.reconcileListeners(cfg)
	app.startListenerRetry()
	select {}
}

func NewRouteManager(app *App, workers int) *RouteManager {
	rm := &RouteManager{
		app:             app,
		ipCache:         make(map[string]routeCacheEntry),
		cidrCache:       make(map[string]routeCacheEntry),
		resetAfterApply: make(map[string]struct{}),
		queue:           make(chan string, 1024),
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
		if err := rm.processIP(ip); err != nil {
			log.Printf("ROUTE_PROCESS_ERROR ip=%s error=%v", ip, err)
		}
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
		ipString := routeIP.String()
		if _, ok := unique[ipString]; ok {
			continue
		}
		unique[ipString] = struct{}{}

		defaultCIDR := defaultCIDRForIP(routeIP)
		if rm.ipCoveredBySnapshot(routeIP) {
			rm.completeIPApplied(ipString, defaultCIDR, false)
			continue
		}

		shouldQueue := false
		rm.ipMu.Lock()
		ent, ok := rm.ipCache[ipString]
		if ok && ent.State == StateApplied {
			rm.ipMu.Unlock()
			continue
		}

		// The DNS answer has already been sent. Record that a successful route
		// completion must invalidate any flow that raced with route installation.
		rm.resetMu.Lock()
		rm.resetAfterApply[ipString] = struct{}{}
		rm.resetMu.Unlock()

		if !ok || ent.State != StatePending {
			rm.ipCache[ipString] = routeCacheEntry{State: StatePending, CIDR: defaultCIDR, UpdatedAt: now}
			shouldQueue = true
		}
		rm.ipMu.Unlock()

		if !shouldQueue {
			continue
		}
		select {
		case rm.queue <- ipString:
		default:
			atomic.AddUint64(&rm.app.routeQueueDrops, 1)
			rm.markIPFailed(ipString, defaultCIDR, time.Now())
			log.Printf("ROUTE_QUEUE_FULL ip=%s cidr=%s queue_len=%d queue_cap=%d; route will be retried on the next DNS answer", ipString, defaultCIDR, len(rm.queue), cap(rm.queue))
		}
	}
}

// EnsureIPsAndWait ensures routes for the supplied addresses and returns only
// after every route is present or at least one route attempt has failed.
func (rm *RouteManager) EnsureIPsAndWait(ips []net.IP) error {
	unique := make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		routeIP := normalizeRouteIP(ip)
		if routeIP != nil {
			unique[routeIP.String()] = routeIP
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(unique))
	for ipString, routeIP := range unique {
		defaultCIDR := defaultCIDRForIP(routeIP)
		if rm.ipCoveredBySnapshot(routeIP) {
			rm.completeIPApplied(ipString, defaultCIDR, false)
			continue
		}

		rm.ipMu.Lock()
		ent, ok := rm.ipCache[ipString]
		if ok && ent.State == StateApplied {
			rm.ipMu.Unlock()
			continue
		}
		if !ok || ent.State != StatePending {
			rm.ipCache[ipString] = routeCacheEntry{State: StatePending, CIDR: defaultCIDR, UpdatedAt: time.Now()}
		}
		rm.ipMu.Unlock()

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if err := rm.processIP(ip); err != nil {
				errCh <- fmt.Errorf("route for %s: %w", ip, err)
			}
		}(ipString)
	}
	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// processIP serializes all work for one destination IP. A synchronous DNS
// request can therefore join an already queued asynchronous route operation.
func (rm *RouteManager) processIP(ip string) error {
	_, err, _ := rm.processGroup.Do(ip, func() (any, error) {
		return nil, rm.processIPOnce(ip)
	})
	return err
}

func (rm *RouteManager) processIPOnce(ip string) error {
	cfg := rm.app.getConfig()
	parsed := normalizeRouteIP(net.ParseIP(ip))
	if parsed == nil {
		return fmt.Errorf("invalid route IP %q", ip)
	}
	ip = parsed.String()

	defaultCIDR := defaultCIDRForIP(parsed)
	if rm.ipCoveredBySnapshot(parsed) {
		rm.completeIPApplied(ip, defaultCIDR, false)
		return nil
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
		rm.markCIDRApplied(cidr, time.Now())
		rm.completeIPApplied(ip, cidr, false)
		return nil
	}

	applyResult, applyErr, _ := rm.applyGroup.Do(cidr, func() (any, error) {
		if rm.cidrCoveredBySnapshot(cidr) {
			rm.markCIDRApplied(cidr, time.Now())
			return false, nil
		}

		// Refresh from the kernel immediately before RouteReplace. The in-memory
		// snapshot may not yet contain a route installed by another process. If
		// the prefix is already covered, no routing change is required and any
		// existing conntrack state must be left untouched.
		routeAbsentConfirmed := false
		if reloadErr := rm.ReloadSnapshot(); reloadErr != nil {
			// Continue trying to install the route, but suppress conntrack reset:
			// without a successful live precheck we cannot prove that the route did
			// not already exist.
			log.Printf("ROUTE_PRECHECK_RELOAD_ERROR ip=%s cidr=%s error=%v", ip, cidr, reloadErr)
		} else if rm.cidrCoveredBySnapshot(cidr) {
			rm.markCIDRApplied(cidr, time.Now())
			return false, nil
		} else {
			routeAbsentConfirmed = true
		}

		rm.cidrMu.Lock()
		rm.cidrCache[cidr] = routeCacheEntry{State: StatePending, CIDR: cidr, UpdatedAt: time.Now()}
		rm.cidrMu.Unlock()

		if err := rm.app.addRoute(cidr); err != nil {
			atomic.AddUint64(&rm.app.routeAddErrors, 1)
			reloadErr := rm.ReloadSnapshot()
			recovered := reloadErr == nil && rm.cidrCoveredBySnapshot(cidr)
			rm.app.recordRouteAddError(ip, cidr, err, reloadErr, recovered)
			if recovered {
				rm.markCIDRApplied(cidr, time.Now())
				// The route appeared without a successful RouteReplace from this
				// operation. Do not disturb existing conntrack entries.
				return false, nil
			}
			rm.markCIDRFailed(cidr, time.Now())
			return false, err
		}

		atomic.AddUint64(&rm.app.routeAdds, 1)
		rm.addCIDRToSnapshot(cidr)
		rm.markCIDRApplied(cidr, time.Now())
		// Reset conntrack only when the live kernel precheck confirmed that the
		// route was absent before our successful RouteReplace.
		return routeAbsentConfirmed, nil
	})

	if applyErr != nil {
		rm.markIPFailed(ip, cidr, time.Now())
		return applyErr
	}
	routeReplaced, _ := applyResult.(bool)
	rm.completeIPApplied(ip, cidr, routeReplaced)
	return nil
}

func (rm *RouteManager) completeIPApplied(ip, cidr string, routeReplaced bool) {
	// Mark the route applied before consuming the pending reset request.
	// A reset is allowed only when this operation observed a successful
	// RouteReplace. Merely finding the address/prefix in the route table must
	// never disturb an already valid connection.
	rm.ipMu.Lock()
	rm.ipCache[ip] = routeCacheEntry{State: StateApplied, CIDR: cidr, UpdatedAt: time.Now()}
	rm.resetMu.Lock()
	_, resetRequested := rm.resetAfterApply[ip]
	delete(rm.resetAfterApply, ip)
	rm.resetMu.Unlock()
	rm.ipMu.Unlock()

	if routeReplaced && resetRequested {
		rm.app.resetConntrackForIP(ip)
	}
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
	return effectiveRouteTable(cfg.RouteTable)
}

func (rm *RouteManager) ResetCaches() {
	rm.ipMu.Lock()
	rm.ipCache = make(map[string]routeCacheEntry)
	rm.ipMu.Unlock()

	rm.cidrMu.Lock()
	rm.cidrCache = make(map[string]routeCacheEntry)
	rm.cidrMu.Unlock()
}

func (rm *RouteManager) ReloadSnapshot() error {
	filter := &netlink.Route{Table: rm.routeTableForLookup()}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("route list filtered: %w", err)
	}
	prefixes := make([]netip.Prefix, 0, len(routes))
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		prefix, parseErr := netip.ParsePrefix(r.Dst.String())
		if parseErr != nil {
			log.Printf("ROUTE_SNAPSHOT_SKIP dst=%q error=%v", r.Dst.String(), parseErr)
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	rm.snapMu.Lock()
	rm.snapshot = prefixes
	rm.snapMu.Unlock()
	return nil
}

func (rm *RouteManager) addCIDRToSnapshot(cidr string) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return
	}
	prefix = prefix.Masked()
	rm.snapMu.Lock()
	defer rm.snapMu.Unlock()
	for _, existing := range rm.snapshot {
		if existing == prefix {
			return
		}
	}
	rm.snapshot = append(rm.snapshot, prefix)
}

func (rm *RouteManager) ipCoveredBySnapshot(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()

	rm.snapMu.RLock()
	defer rm.snapMu.RUnlock()
	for _, prefix := range rm.snapshot {
		if prefix.Addr().Is4() != addr.Is4() {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (rm *RouteManager) cidrCoveredBySnapshot(cidr string) bool {
	want, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	want = want.Masked()

	rm.snapMu.RLock()
	defer rm.snapMu.RUnlock()
	for _, have := range rm.snapshot {
		if prefixCovers(have, want) {
			return true
		}
	}
	return false
}

// prefixCovers reports whether every address in want is contained in have.
// Checking only have.Contains(want.Addr()) is insufficient: 10.0.0.0/25
// contains the network address of 10.0.0.0/24 but not the whole /24.
func prefixCovers(have, want netip.Prefix) bool {
	if !have.IsValid() || !want.IsValid() {
		return false
	}

	have = have.Masked()
	want = want.Masked()
	if have.Addr().BitLen() != want.Addr().BitLen() {
		return false
	}
	if have.Bits() > want.Bits() {
		return false
	}
	return have.Contains(want.Addr())
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

func effectiveRouteTable(table int) int {
	if table == 0 {
		return mainRouteTable
	}
	return table
}

func logConfig(prefix string, cfg *Config) {
	log.Printf(
		"%s: LISTEN=%v LISTENER_FREEBIND=%t UPSTREAMS=%v FORWARD_ZONES=%d FORWARD_ZONE_UPSTREAMS=%d WG_INTERFACE=%s WG_GATEWAY=%s WG_GATEWAY_V4=%s WG_GATEWAY_V6=%s ROUTE_TABLE=%d ROUTE_IPV4=%t ROUTE_IPV6=%t LOOKUP_CYMRU_PREFIX=%t REPLY_BEFORE_ROUTE=%t SPECIAL_DOMAINS=%d LOCAL_A=%d LOCAL_AAAA=%d",
		prefix, cfg.ListenAddrs, cfg.ListenerFreeBind, cfg.Upstreams, len(cfg.ForwardZones), forwardZoneUpstreamCount(cfg), cfg.WGInterface, cfg.WGGateway, cfg.WGGatewayV4, cfg.WGGatewayV6, cfg.RouteTable,
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

func (a *App) validateTemplates() error {
	cfg := a.getConfig()
	adminData := pageData{
		Config:         cfg,
		Settings:       map[string]string{},
		ListenAddrs:    append([]string(nil), cfg.ListenAddrs...),
		ListenerStates: a.listenerViews(),
		Upstreams:      a.defaultUpstreamViews(cfg),
		ForwardZones:   a.forwardZoneViews(cfg),
		SpecialDomains: []string{},
		Records:        []recordRow{},
		Message:        a.adminAddr,
	}
	if err := templates.ExecuteTemplate(io.Discard, "admin.html.tmpl", adminData); err != nil {
		return fmt.Errorf("admin.html.tmpl: %w", err)
	}
	if err := templates.ExecuteTemplate(io.Discard, "stats.html.tmpl", a.statsSnapshot()); err != nil {
		return fmt.Errorf("stats.html.tmpl: %w", err)
	}
	if err := templates.ExecuteTemplate(io.Discard, "error.html.tmpl", struct{ Error string }{Error: "test"}); err != nil {
		return fmt.Errorf("error.html.tmpl: %w", err)
	}
	return nil
}

func loadConfigFromDB(db *sql.DB) (*Config, error) {
	cfg := &Config{
		UpstreamProto:    make(map[string]string),
		SpecialDomains:   make(map[string]struct{}),
		LocalA:           make(map[string][]LocalRecord),
		LocalAAAA:        make(map[string][]LocalRecord),
		DefaultTTL:       60,
		RouteTable:       0,
		RouteIPv4:        true,
		RouteIPv6:        true,
		LookupCIDR:       true,
		ReplyBeforeRoute: false,
		ListenerFreeBind: false,
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
	if v := strings.TrimSpace(settings["listener_freebind"]); v != "" {
		cfg.ListenerFreeBind = isTrueString(v)
	}
	if err := readListenAddrs(db, cfg); err != nil {
		return nil, err
	}
	if err := readUpstreams(db, cfg); err != nil {
		return nil, err
	}
	if err := readForwardZones(db, cfg); err != nil {
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

func formBoolean(r *http.Request, name string) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	for _, value := range r.PostForm[name] {
		if isTrueString(value) {
			return true
		}
	}
	return false
}

func boolSetting(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func initDB(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
		`CREATE TABLE IF NOT EXISTS listen_addrs (id INTEGER PRIMARY KEY AUTOINCREMENT, addr TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);`,
		`CREATE TABLE IF NOT EXISTS upstreams (id INTEGER PRIMARY KEY AUTOINCREMENT, addr TEXT NOT NULL UNIQUE, proto TEXT NOT NULL DEFAULT 'auto', enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 100);`,
		`CREATE TABLE IF NOT EXISTS forward_zones (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);`,
		`CREATE TABLE IF NOT EXISTS forward_zone_upstreams (id INTEGER PRIMARY KEY AUTOINCREMENT, zone_id INTEGER NOT NULL, addr TEXT NOT NULL, proto TEXT NOT NULL DEFAULT 'auto', enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 100, UNIQUE(zone_id, addr));`,
		`CREATE INDEX IF NOT EXISTS idx_forward_zone_upstreams_zone ON forward_zone_upstreams(zone_id, enabled, priority, id);`,
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
	rows, err := db.Query(`SELECT addr, proto FROM upstreams WHERE enabled = 1 ORDER BY priority, id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var addr, proto string
		if err := rows.Scan(&addr, &proto); err != nil {
			return err
		}
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		proto = strings.ToLower(strings.TrimSpace(proto))
		if proto == "" {
			proto = "auto"
		}
		cfg.Upstreams = append(cfg.Upstreams, addr)
		cfg.UpstreamProto[addr] = proto
	}
	return rows.Err()
}
func readForwardZones(db *sql.DB, cfg *Config) error {
	rows, err := db.Query(`SELECT id, domain FROM forward_zones WHERE enabled = 1 ORDER BY length(domain) DESC, domain`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var zones []ForwardZone
	for rows.Next() {
		var zone ForwardZone
		if err := rows.Scan(&zone.ID, &zone.Domain); err != nil {
			return err
		}
		zone.Domain = normalizeName(zone.Domain)
		if zone.Domain == "" {
			continue
		}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for i := range zones {
		upRows, err := db.Query(`SELECT id, addr, proto, priority FROM forward_zone_upstreams WHERE zone_id = ? AND enabled = 1 ORDER BY priority, id`, zones[i].ID)
		if err != nil {
			return err
		}
		for upRows.Next() {
			var upstream ForwardZoneUpstream
			if err := upRows.Scan(&upstream.ID, &upstream.Addr, &upstream.Proto, &upstream.Priority); err != nil {
				_ = upRows.Close()
				return err
			}
			upstream.Addr = strings.TrimSpace(upstream.Addr)
			upstream.Proto = canonicalUpstreamProto(upstream.Proto)
			if upstream.Addr == "" {
				continue
			}
			zones[i].Upstreams = append(zones[i].Upstreams, upstream)
		}
		if err := upRows.Err(); err != nil {
			_ = upRows.Close()
			return err
		}
		_ = upRows.Close()
	}
	cfg.ForwardZones = zones
	return nil
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
func normalizeForwardZone(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	value = normalizeName(value)
	if value == "" || value == "*" {
		return "", fmt.Errorf("forward zone cannot be empty or the default root")
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(value)); !ok {
		return "", fmt.Errorf("invalid forward zone %q", value)
	}
	return value, nil
}

func domainMatchesZone(name, zone string) bool {
	name = normalizeName(name)
	zone = normalizeName(zone)
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func defaultUpstreamTargets(cfg *Config) []upstreamTarget {
	if cfg == nil {
		return nil
	}
	out := make([]upstreamTarget, 0, len(cfg.Upstreams))
	for _, addr := range cfg.Upstreams {
		out = append(out, upstreamTarget{Addr: addr, Proto: cfg.UpstreamProto[addr]})
	}
	return out
}

func allConfiguredUpstreamTargets(cfg *Config) []upstreamTarget {
	if cfg == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []upstreamTarget
	add := func(target upstreamTarget) {
		target.Addr = strings.TrimSpace(target.Addr)
		target.Proto = canonicalUpstreamProto(target.Proto)
		if target.Addr == "" {
			return
		}
		key := upstreamCircuitKey(target.Addr, target.Proto)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, target)
	}
	for _, target := range defaultUpstreamTargets(cfg) {
		add(target)
	}
	for _, zone := range cfg.ForwardZones {
		for _, upstream := range zone.Upstreams {
			add(upstreamTarget{Addr: upstream.Addr, Proto: upstream.Proto})
		}
	}
	return out
}

func forwardZoneUpstreamCount(cfg *Config) int {
	if cfg == nil {
		return 0
	}
	total := 0
	for _, zone := range cfg.ForwardZones {
		total += len(zone.Upstreams)
	}
	return total
}

func buildForwardPolicy(key, domain string, targets []upstreamTarget) forwardPolicy {
	fingerprint := make([]string, 0, len(targets))
	for _, target := range targets {
		fingerprint = append(fingerprint, upstreamCircuitKey(target.Addr, target.Proto))
	}
	sort.Strings(fingerprint)
	return forwardPolicy{
		Key:       key,
		Domain:    domain,
		CacheKey:  key + "|" + strings.Join(fingerprint, ","),
		Upstreams: append([]upstreamTarget(nil), targets...),
	}
}

func forwardPolicyForName(name string, cfg *Config) forwardPolicy {
	name = normalizeName(name)
	var best *ForwardZone
	for i := range cfg.ForwardZones {
		zone := &cfg.ForwardZones[i]
		if len(zone.Upstreams) == 0 || !domainMatchesZone(name, zone.Domain) {
			continue
		}
		if best == nil || len(zone.Domain) > len(best.Domain) {
			best = zone
		}
	}
	if best != nil {
		targets := make([]upstreamTarget, 0, len(best.Upstreams))
		for _, upstream := range best.Upstreams {
			targets = append(targets, upstreamTarget{Addr: upstream.Addr, Proto: upstream.Proto})
		}
		return buildForwardPolicy(best.Domain, best.Domain, targets)
	}
	return buildForwardPolicy("default", "", defaultUpstreamTargets(cfg))
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
	a.syncUpstreamCircuits(cfg)
	a.setConfig(cfg)
	a.reconcileListeners(cfg)
	a.routeMgr.ResetCaches()
	if err := a.routeMgr.ReloadSnapshot(); err != nil {
		return fmt.Errorf("reload route snapshot after config change: %w", err)
	}
	logConfig("CONFIG reloaded", cfg)
	return nil
}

func (a *App) startListenerRetry() {
	go func() {
		ticker := time.NewTicker(listenerRetryInterval)
		defer ticker.Stop()
		for range ticker.C {
			a.reconcileListeners(a.getConfig())
		}
	}()
}

func (a *App) reconcileListeners(cfg *Config) {
	if cfg == nil {
		return
	}
	a.listenerReconcileMu.Lock()
	defer a.listenerReconcileMu.Unlock()

	desiredSpecs := buildListenerSpecs(cfg.ListenAddrs)
	desired := make(map[string]listenerSpec, len(desiredSpecs))
	for _, spec := range desiredSpecs {
		desired[spec.Key()] = spec
	}

	var toStop []*managedListener
	a.srvMu.Lock()
	for key, active := range a.servers {
		_, wanted := desired[key]
		if !wanted || active.FreeBind != cfg.ListenerFreeBind {
			delete(a.servers, key)
			toStop = append(toStop, active)
		}
	}
	for key, pending := range a.pendingListeners {
		_, wanted := desired[key]
		if !wanted || pending.FreeBind != cfg.ListenerFreeBind {
			delete(a.pendingListeners, key)
		}
	}
	a.srvMu.Unlock()

	for _, active := range toStop {
		if err := active.Server.Shutdown(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("listener shutdown error for %s: %v", active.Spec.Key(), err)
		}
	}

	for _, spec := range desiredSpecs {
		key := spec.Key()
		a.srvMu.Lock()
		_, active := a.servers[key]
		previousPending := a.pendingListeners[key]
		a.srvMu.Unlock()
		if active {
			continue
		}

		atomic.AddUint64(&a.listenerBindAttempts, 1)
		srv, err := a.newServer(spec, cfg.ListenerFreeBind)
		now := time.Now()
		if err != nil {
			atomic.AddUint64(&a.listenerBindErrors, 1)
			a.srvMu.Lock()
			pending := a.pendingListeners[key]
			if pending == nil {
				pending = &pendingListener{Spec: spec, FreeBind: cfg.ListenerFreeBind}
				a.pendingListeners[key] = pending
			}
			oldError := pending.LastError
			pending.Attempts++
			pending.LastAttempt = now
			pending.LastError = err.Error()
			attempts := pending.Attempts
			a.srvMu.Unlock()

			if previousPending == nil || oldError != err.Error() || attempts%20 == 0 {
				log.Printf(
					"LISTENER_PENDING network=%s addr=%q freebind=%t attempts=%d retry_in=%s error=%v",
					spec.Net,
					spec.Addr,
					cfg.ListenerFreeBind,
					attempts,
					listenerRetryInterval,
					err,
				)
			}
			continue
		}

		managed := &managedListener{
			Server:    srv,
			Spec:      spec,
			FreeBind:  cfg.ListenerFreeBind,
			StartedAt: now,
		}
		a.srvMu.Lock()
		_, recovered := a.pendingListeners[key]
		delete(a.pendingListeners, key)
		a.servers[key] = managed
		a.srvMu.Unlock()

		atomic.AddUint64(&a.listenerStarts, 1)
		if recovered {
			atomic.AddUint64(&a.listenerRecoveries, 1)
		}
		log.Printf(
			"LISTENER_ACTIVE network=%s addr=%q freebind=%t recovered=%t",
			spec.Net,
			spec.Addr,
			cfg.ListenerFreeBind,
			recovered,
		)
		go a.serveLoop(managed)
	}
}

func enableListenerFreeBind(fd uintptr, network, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("split listen address %q: %w", address, err)
	}
	host = strings.Trim(host, "[]")
	if zoneIndex := strings.LastIndexByte(host, '%'); zoneIndex >= 0 {
		host = host[:zoneIndex]
	}
	ip := net.ParseIP(host)
	isIPv6 := strings.HasSuffix(network, "6") || (ip != nil && ip.To4() == nil)
	if isIPv6 {
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6FreeBind, 1); err != nil {
			return fmt.Errorf("set IPV6_FREEBIND: %w", err)
		}
		return nil
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_FREEBIND, 1); err != nil {
		return fmt.Errorf("set IP_FREEBIND: %w", err)
	}
	return nil
}

func listenerListenConfig(freeBind bool) net.ListenConfig {
	lc := net.ListenConfig{}
	if !freeBind {
		return lc
	}
	lc.Control = func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = enableListenerFreeBind(fd, network, address)
		}); err != nil {
			return err
		}
		return socketErr
	}
	return lc
}

func (a *App) newServer(spec listenerSpec, freeBind bool) (*dns.Server, error) {
	handler := dns.HandlerFunc(a.handleDNS)
	lc := listenerListenConfig(freeBind)
	switch spec.Net {
	case "udp":
		pc, err := lc.ListenPacket(context.Background(), "udp", spec.Addr)
		if err != nil {
			return nil, err
		}
		return &dns.Server{Net: "udp", PacketConn: pc, Handler: handler}, nil
	case "tcp":
		ln, err := lc.Listen(context.Background(), "tcp", spec.Addr)
		if err != nil {
			return nil, err
		}
		return &dns.Server{Net: "tcp", Listener: ln, Handler: handler}, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", spec.Net)
	}
}

func (a *App) serveLoop(active *managedListener) {
	err := active.Server.ActivateAndServe()
	if err == nil {
		err = fmt.Errorf("listener stopped unexpectedly")
	}

	key := active.Spec.Key()
	a.srvMu.Lock()
	current, stillActive := a.servers[key]
	if stillActive && current == active {
		delete(a.servers, key)
		a.pendingListeners[key] = &pendingListener{
			Spec:        active.Spec,
			FreeBind:    active.FreeBind,
			LastAttempt: time.Now(),
			LastError:   err.Error(),
		}
	}
	a.srvMu.Unlock()

	if stillActive && current == active {
		log.Printf(
			"LISTENER_EXITED network=%s addr=%q freebind=%t retry_in=%s error=%v",
			active.Spec.Net,
			active.Spec.Addr,
			active.FreeBind,
			listenerRetryInterval,
			err,
		)
	}
}

func (a *App) listenerViews() []listenerView {
	a.srvMu.Lock()
	out := make([]listenerView, 0, len(a.servers)+len(a.pendingListeners))
	for _, active := range a.servers {
		out = append(out, listenerView{
			Net:       active.Spec.Net,
			Addr:      active.Spec.Addr,
			State:     "active",
			FreeBind:  active.FreeBind,
			StartedAt: active.StartedAt.Format(time.RFC3339),
		})
	}
	for _, pending := range a.pendingListeners {
		lastAttempt := "—"
		if !pending.LastAttempt.IsZero() {
			lastAttempt = pending.LastAttempt.Format(time.RFC3339)
		}
		out = append(out, listenerView{
			Net:         pending.Spec.Net,
			Addr:        pending.Spec.Addr,
			State:       "pending",
			FreeBind:    pending.FreeBind,
			Attempts:    pending.Attempts,
			LastAttempt: lastAttempt,
			LastError:   pending.LastError,
		})
	}
	a.srvMu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Net < out[j].Net
	})
	return out
}

func (a *App) startHTTP() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleAdmin)
	mux.HandleFunc("/reload", a.handleReload)
	mux.HandleFunc("/routes/reload", a.handleRoutesReload)
	mux.HandleFunc("/routes/errors", a.handleRouteErrors)
	mux.HandleFunc("/stats", a.handleStats)
	mux.HandleFunc("/metrics", a.handleMetrics)
	mux.HandleFunc("/settings/save", a.handleSettingsSave)
	mux.HandleFunc("/listen/add", a.handleListenAdd)
	mux.HandleFunc("/listen/delete", a.handleListenDelete)
	mux.HandleFunc("/upstream/add", a.handleUpstreamAdd)
	mux.HandleFunc("/upstream/delete", a.handleUpstreamDelete)
	mux.HandleFunc("/forward-zone/add", a.handleForwardZoneAdd)
	mux.HandleFunc("/forward-zone/upstream/delete", a.handleForwardZoneUpstreamDelete)
	mux.HandleFunc("/forward-zone/delete", a.handleForwardZoneDelete)
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
	cfg := a.getConfig()
	upstreams := a.defaultUpstreamViews(cfg)
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
	data := pageData{Config: cfg, Settings: settings, ListenAddrs: listenAddrs, ListenerStates: a.listenerViews(), Upstreams: upstreams, ForwardZones: a.forwardZoneViews(cfg), SpecialDomains: specials, Records: records, Message: a.adminAddr}
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

func (a *App) handleRouteErrors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	a.routeErrMu.Lock()
	out := append([]routeErrorDiagnostic(nil), a.routeErrorLog...)
	a.routeErrMu.Unlock()

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Printf("write route error history: %v", err)
	}
}

func (a *App) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, 405, fmt.Errorf("method not allowed"))
		return
	}
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, fmt.Errorf("parse settings form: %w", err))
		return
	}
	lookupCIDR := boolSetting(formBoolean(r, "lookup_cidr"))
	replyBeforeRoute := boolSetting(formBoolean(r, "reply_before_route"))
	listenerFreeBind := boolSetting(formBoolean(r, "listener_freebind"))
	routeIPv4 := boolSetting(formBoolean(r, "route_ipv4"))
	routeIPv6 := boolSetting(formBoolean(r, "route_ipv6"))
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
		"listener_freebind":  listenerFreeBind,
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
	proto := strings.ToLower(strings.TrimSpace(r.FormValue("proto")))
	if proto == "" {
		proto = "auto"
	}
	if !validUpstreamProto(proto) {
		renderError(w, 400, fmt.Errorf("unsupported upstream protocol %q", proto))
		return
	}
	if _, _, err := resolveUpstream(addr, proto); err != nil {
		renderError(w, 400, err)
		return
	}
	if _, err := a.db.Exec(`INSERT INTO upstreams(addr, proto, enabled, priority) VALUES(?, ?, 1, 100) ON CONFLICT(addr) DO UPDATE SET proto = excluded.proto, enabled = 1`, addr, proto); err != nil {
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
func (a *App) handleForwardZoneAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	domain, err := normalizeForwardZone(r.FormValue("domain"))
	if err != nil {
		renderError(w, http.StatusBadRequest, err)
		return
	}
	addr := strings.TrimSpace(r.FormValue("addr"))
	if addr == "" {
		renderError(w, http.StatusBadRequest, fmt.Errorf("upstream address is required"))
		return
	}
	proto := canonicalUpstreamProto(r.FormValue("proto"))
	if !validUpstreamProto(proto) {
		renderError(w, http.StatusBadRequest, fmt.Errorf("unsupported upstream protocol %q", proto))
		return
	}
	if _, _, err := resolveUpstream(addr, proto); err != nil {
		renderError(w, http.StatusBadRequest, err)
		return
	}

	tx, err := a.db.Begin()
	if err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO forward_zones(domain, enabled) VALUES(?, 1) ON CONFLICT(domain) DO UPDATE SET enabled = 1`, domain); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	var zoneID int64
	if err := tx.QueryRow(`SELECT id FROM forward_zones WHERE domain = ?`, domain).Scan(&zoneID); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if _, err := tx.Exec(`INSERT INTO forward_zone_upstreams(zone_id, addr, proto, enabled, priority) VALUES(?, ?, ?, 1, 100) ON CONFLICT(zone_id, addr) DO UPDATE SET proto = excluded.proto, enabled = 1`, zoneID, addr, proto); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := tx.Commit(); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleForwardZoneUpstreamDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		renderError(w, http.StatusBadRequest, fmt.Errorf("invalid forward-zone upstream id"))
		return
	}
	if _, err := a.db.Exec(`DELETE FROM forward_zone_upstreams WHERE id = ?`, id); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleForwardZoneDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		renderError(w, http.StatusBadRequest, fmt.Errorf("invalid forward-zone id"))
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM forward_zone_upstreams WHERE zone_id = ?`, id); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if _, err := tx.Exec(`DELETE FROM forward_zones WHERE id = ?`, id); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := tx.Commit(); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadConfig(); err != nil {
		renderError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

	if resp := a.localResponse(req, q); resp != nil {
		cfg := a.getConfig()
		ips := a.routeIPsFromAnswers(name, q.Qtype, resp.Answer, cfg)
		if cfg.ReplyBeforeRoute {
			atomic.AddUint64(&a.localAnswers, 1)
			_ = writeDNSResponse(w, req, resp)
			if len(ips) > 0 {
				a.routeMgr.EnsureIPs(ips)
			}
			return
		}
		if len(ips) > 0 {
			if err := a.routeMgr.EnsureIPsAndWait(ips); err != nil {
				atomic.AddUint64(&a.servfailCount, 1)
				log.Printf("ROUTE_BEFORE_REPLY_ERROR name=%s qtype=%s local=true error=%v", name, dns.TypeToString[q.Qtype], err)
				respondSERVFAIL(w, req)
				return
			}
		}
		atomic.AddUint64(&a.localAnswers, 1)
		_ = writeDNSResponse(w, req, resp)
		return
	}

	cfgForPolicy := a.getConfig()
	policy := forwardPolicyForName(name, cfgForPolicy)
	key := policy.CacheKey + "|" + name + ":" + dns.TypeToString[q.Qtype]

	a.cacheMu.RLock()
	if entry, ok := a.cache[key]; ok && time.Now().Before(entry.expiration) {
		a.cacheMu.RUnlock()
		atomic.AddUint64(&a.cacheHits, 1)
		cached := entry.msg.Copy()
		cached.Id = req.Id
		cfg := a.getConfig()
		ips := a.routeIPsFromAnswers(name, q.Qtype, cached.Answer, cfg)
		if cfg.ReplyBeforeRoute {
			_ = writeDNSResponse(w, req, cached)
			if len(ips) > 0 {
				a.routeMgr.EnsureIPs(ips)
			}
			return
		}
		if len(ips) > 0 {
			if err := a.routeMgr.EnsureIPsAndWait(ips); err != nil {
				atomic.AddUint64(&a.servfailCount, 1)
				log.Printf("ROUTE_BEFORE_REPLY_ERROR name=%s qtype=%s cached=true error=%v", name, dns.TypeToString[q.Qtype], err)
				respondSERVFAIL(w, req)
				return
			}
		}
		_ = writeDNSResponse(w, req, cached)
		return
	}
	a.cacheMu.RUnlock()
	atomic.AddUint64(&a.cacheMisses, 1)

	resp, err := a.forwardDNSWithPolicy(req, policy)
	if err != nil {
		atomic.AddUint64(&a.forwardErrors, 1)
		atomic.AddUint64(&a.servfailCount, 1)
		a.logForwardError(name, q.Qtype, err)
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
		_ = writeDNSResponse(w, req, resp)
		atomic.AddUint64(&a.forwardedOK, 1)
		if len(ips) > 0 {
			a.routeMgr.EnsureIPs(ips)
		}
		return
	}

	if len(ips) > 0 {
		if err := a.routeMgr.EnsureIPsAndWait(ips); err != nil {
			atomic.AddUint64(&a.servfailCount, 1)
			log.Printf("ROUTE_BEFORE_REPLY_ERROR name=%s qtype=%s cached=false error=%v", name, dns.TypeToString[q.Qtype], err)
			respondSERVFAIL(w, req)
			return
		}
	}
	_ = writeDNSResponse(w, req, resp)
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

func newDoHClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: transport}
}

func validUpstreamProto(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "auto", "udp", "dns", "tcp", "tls", "dot", "https", "doh":
		return true
	default:
		return false
	}
}

func canonicalUpstreamProto(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "dns":
		return "udp"
	case "dot":
		return "tls"
	case "doh":
		return "https"
	default:
		return strings.ToLower(strings.TrimSpace(proto))
	}
}

// resolveUpstream converts the database protocol and optional address scheme
// into a canonical protocol and endpoint. Existing address-only entries remain
// compatible: port 853 means DoT, every other port means ordinary UDP DNS.
func resolveUpstream(rawAddr, configuredProto string) (proto, endpoint string, err error) {
	endpoint = strings.TrimSpace(rawAddr)
	if endpoint == "" {
		return "", "", fmt.Errorf("empty upstream address")
	}

	proto = canonicalUpstreamProto(configuredProto)
	if proto == "" {
		proto = "auto"
	}
	if !validUpstreamProto(proto) {
		return "", "", fmt.Errorf("unsupported upstream protocol %q for %q", configuredProto, rawAddr)
	}

	lower := strings.ToLower(endpoint)
	schemeProto := ""
	switch {
	case strings.HasPrefix(lower, "https://"):
		schemeProto = "https"
	case strings.HasPrefix(lower, "doh://"):
		schemeProto = "https"
		endpoint = "https://" + endpoint[len("doh://"):]
	case strings.HasPrefix(lower, "tls://"):
		schemeProto = "tls"
		endpoint = endpoint[len("tls://"):]
	case strings.HasPrefix(lower, "dot://"):
		schemeProto = "tls"
		endpoint = endpoint[len("dot://"):]
	case strings.HasPrefix(lower, "tcp://"):
		schemeProto = "tcp"
		endpoint = endpoint[len("tcp://"):]
	case strings.HasPrefix(lower, "udp://"):
		schemeProto = "udp"
		endpoint = endpoint[len("udp://"):]
	case strings.HasPrefix(lower, "dns://"):
		schemeProto = "udp"
		endpoint = endpoint[len("dns://"):]
	}

	if proto == "auto" && schemeProto != "" {
		proto = schemeProto
	} else if proto != "auto" && schemeProto != "" && proto != schemeProto {
		return "", "", fmt.Errorf("upstream protocol %q conflicts with address %q", configuredProto, rawAddr)
	}

	if proto == "auto" {
		if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
			proto = "https"
		} else if _, port, splitErr := net.SplitHostPort(endpoint); splitErr == nil && port == "853" {
			proto = "tls"
		} else {
			proto = "udp"
		}
	}

	if proto == "https" {
		if !strings.HasPrefix(strings.ToLower(endpoint), "https://") {
			return "", "", fmt.Errorf("DoH upstream must be an https URL: %q", rawAddr)
		}
		return proto, endpoint, nil
	}

	defaultPort := "53"
	if proto == "tls" {
		defaultPort = "853"
	}
	endpoint, err = upstreamAddrWithDefaultPort(endpoint, defaultPort)
	if err != nil {
		return "", "", fmt.Errorf("invalid %s upstream %q: %w", proto, rawAddr, err)
	}
	return proto, endpoint, nil
}

func upstreamAddrWithDefaultPort(addr, defaultPort string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("empty address")
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr, nil
	}
	if ip := net.ParseIP(addr); ip != nil {
		return net.JoinHostPort(addr, defaultPort), nil
	}
	if !strings.Contains(addr, ":") {
		return net.JoinHostPort(addr, defaultPort), nil
	}
	return "", fmt.Errorf("address must be host:port; IPv6 literals must use brackets")
}

func (a *App) exchangeDoH(req *dns.Msg, endpoint string) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack request: %w", err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	client := a.dohClient
	if client == nil {
		client = newDoHClient()
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 65536))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected HTTP status %s", httpResp.Status)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DoH response: %w", err)
	}
	return resp, nil
}

func exchangeClassicDNS(req *dns.Msg, proto, endpoint string) (*dns.Msg, error) {
	network := proto
	client := &dns.Client{Timeout: 5 * time.Second}
	switch proto {
	case "udp":
		client.Net = "udp"
	case "tcp":
		client.Net = "tcp"
	case "tls":
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	default:
		return nil, fmt.Errorf("unsupported DNS transport %q", proto)
	}

	resp, _, err := client.Exchange(req, endpoint)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty %s response", network)
	}
	if proto == "udp" && resp.Truncated {
		tcpClient := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
		resp, _, err = tcpClient.Exchange(req, endpoint)
		if err != nil {
			return nil, fmt.Errorf("UDP response truncated; TCP retry failed: %w", err)
		}
		if resp == nil {
			return nil, fmt.Errorf("UDP response truncated; empty TCP response")
		}
	}
	return resp, nil
}

func upstreamCircuitKey(rawAddr, configuredProto string) string {
	proto := canonicalUpstreamProto(configuredProto)
	if proto == "" {
		proto = "auto"
	}
	return strings.TrimSpace(rawAddr) + "\x00" + proto
}

func upstreamCircuitProtoLabel(rawAddr, configuredProto string) string {
	proto, _, err := resolveUpstream(rawAddr, configuredProto)
	if err == nil {
		return proto
	}
	proto = canonicalUpstreamProto(configuredProto)
	if proto == "" {
		return "auto"
	}
	return proto
}

func (a *App) syncUpstreamCircuits(cfg *Config) {
	targets := allConfiguredUpstreamTargets(cfg)
	wanted := make(map[string]struct{}, len(targets))

	a.upstreamMu.Lock()
	defer a.upstreamMu.Unlock()
	if a.upstreamCircuits == nil {
		a.upstreamCircuits = make(map[string]*upstreamCircuit)
	}
	for _, target := range targets {
		configuredProto := canonicalUpstreamProto(target.Proto)
		key := upstreamCircuitKey(target.Addr, configuredProto)
		wanted[key] = struct{}{}
		if existing, ok := a.upstreamCircuits[key]; ok {
			existing.RawAddr = strings.TrimSpace(target.Addr)
			existing.ConfiguredProto = configuredProto
			continue
		}
		a.upstreamCircuits[key] = &upstreamCircuit{
			RawAddr:         strings.TrimSpace(target.Addr),
			ConfiguredProto: configuredProto,
			Proto:           upstreamCircuitProtoLabel(target.Addr, configuredProto),
			State:           upstreamCircuitClosed,
		}
	}
	for key := range a.upstreamCircuits {
		if _, ok := wanted[key]; !ok {
			delete(a.upstreamCircuits, key)
		}
	}
}

func upstreamCircuitBackoff(level uint) time.Duration {
	backoff := upstreamCircuitBaseBackoff
	for i := uint(0); i < level && backoff < upstreamCircuitMaxBackoff; i++ {
		if backoff > upstreamCircuitMaxBackoff/2 {
			return upstreamCircuitMaxBackoff
		}
		backoff *= 2
	}
	if backoff > upstreamCircuitMaxBackoff {
		return upstreamCircuitMaxBackoff
	}
	return backoff
}

// beginUpstreamAttempt returns false while an upstream is in its cooldown.
// After the cooldown expires, exactly one caller is admitted as a half-open
// probe; concurrent callers skip that upstream until the probe completes.
func (a *App) beginUpstreamAttempt(rawAddr, configuredProto, resolvedProto string) (upstreamCircuitAttempt, bool, time.Duration) {
	key := upstreamCircuitKey(rawAddr, configuredProto)
	now := time.Now()

	a.upstreamMu.Lock()
	defer a.upstreamMu.Unlock()
	if a.upstreamCircuits == nil {
		a.upstreamCircuits = make(map[string]*upstreamCircuit)
	}
	c, ok := a.upstreamCircuits[key]
	if !ok {
		return upstreamCircuitAttempt{}, false, 0
	}
	if resolvedProto != "" {
		c.Proto = resolvedProto
	}

	switch c.State {
	case upstreamCircuitOpen:
		if now.Before(c.OpenUntil) {
			c.Skipped++
			return upstreamCircuitAttempt{}, false, time.Until(c.OpenUntil)
		}
		c.State = upstreamCircuitHalfOpen
		c.ProbeInFlight = true
		c.HalfOpenProbes++
		log.Printf("UPSTREAM_CIRCUIT_HALF_OPEN upstream=%q proto=%s", c.RawAddr, c.Proto)
		return upstreamCircuitAttempt{Key: key, Generation: c.Generation, HalfOpen: true}, true, 0
	case upstreamCircuitHalfOpen:
		if c.ProbeInFlight {
			c.Skipped++
			return upstreamCircuitAttempt{}, false, 0
		}
		c.ProbeInFlight = true
		c.HalfOpenProbes++
		return upstreamCircuitAttempt{Key: key, Generation: c.Generation, HalfOpen: true}, true, 0
	default:
		return upstreamCircuitAttempt{Key: key, Generation: c.Generation}, true, 0
	}
}

func (a *App) completeUpstreamTransportSuccess(attempt upstreamCircuitAttempt, usefulAnswer bool) {
	now := time.Now()
	var recovered bool
	var rawAddr, proto string

	a.upstreamMu.Lock()
	c, ok := a.upstreamCircuits[attempt.Key]
	if !ok {
		a.upstreamMu.Unlock()
		return
	}
	if usefulAnswer {
		c.Successes++
	} else {
		c.DNSFailures++
	}
	c.LastSuccess = now
	if attempt.Generation == c.Generation {
		recovered = c.State == upstreamCircuitHalfOpen || c.State == upstreamCircuitOpen
		c.State = upstreamCircuitClosed
		c.ConsecutiveFailures = 0
		c.BackoffLevel = 0
		c.OpenUntil = time.Time{}
		c.ProbeInFlight = false
		c.LastError = ""
		if recovered {
			c.Recoveries++
			c.Generation++
		}
	}
	rawAddr, proto = c.RawAddr, c.Proto
	a.upstreamMu.Unlock()

	if recovered {
		log.Printf("UPSTREAM_CIRCUIT_RECOVERED upstream=%q proto=%s", rawAddr, proto)
	}
}

func (a *App) completeUpstreamSuccess(attempt upstreamCircuitAttempt) {
	a.completeUpstreamTransportSuccess(attempt, true)
}

func (a *App) completeUpstreamDNSFailure(attempt upstreamCircuitAttempt) {
	// A DNS SERVFAIL/REFUSED proves that the transport and server are reachable,
	// so it closes the circuit but is not counted as a useful answer. The caller
	// may continue to another upstream without penalizing this circuit.
	a.completeUpstreamTransportSuccess(attempt, false)
}

func (a *App) completeUpstreamFailure(attempt upstreamCircuitAttempt, err error) {
	now := time.Now()
	var opened bool
	var rawAddr, proto string
	var failures uint64
	var cooldown time.Duration
	var openUntil time.Time

	a.upstreamMu.Lock()
	c, ok := a.upstreamCircuits[attempt.Key]
	if !ok {
		a.upstreamMu.Unlock()
		return
	}
	c.Failures++
	c.LastFailure = now
	c.LastError = err.Error()
	if attempt.Generation == c.Generation {
		c.ConsecutiveFailures++
		if c.State == upstreamCircuitHalfOpen || c.ConsecutiveFailures >= upstreamFailureThreshold {
			cooldown = upstreamCircuitBackoff(c.BackoffLevel)
			if cooldown < upstreamCircuitMaxBackoff {
				c.BackoffLevel++
			}
			c.State = upstreamCircuitOpen
			c.OpenUntil = now.Add(cooldown)
			c.ProbeInFlight = false
			c.OpenEvents++
			c.Generation++
			opened = true
		}
	}
	rawAddr, proto = c.RawAddr, c.Proto
	failures = c.ConsecutiveFailures
	openUntil = c.OpenUntil
	a.upstreamMu.Unlock()

	if opened {
		log.Printf(
			"UPSTREAM_CIRCUIT_OPEN upstream=%q proto=%s consecutive_failures=%d cooldown=%s open_until=%s error=%v",
			rawAddr,
			proto,
			failures,
			cooldown,
			openUntil.Format(time.RFC3339),
			err,
		)
	}
}

func (a *App) upstreamCircuitSnapshots() []upstreamCircuitSnapshot {
	a.upstreamMu.Lock()
	out := make([]upstreamCircuitSnapshot, 0, len(a.upstreamCircuits))
	for _, c := range a.upstreamCircuits {
		out = append(out, upstreamCircuitSnapshot{
			RawAddr:             c.RawAddr,
			ConfiguredProto:     c.ConfiguredProto,
			Proto:               c.Proto,
			State:               c.State,
			ConsecutiveFailures: c.ConsecutiveFailures,
			OpenUntil:           c.OpenUntil,
			Successes:           c.Successes,
			Failures:            c.Failures,
			DNSFailures:         c.DNSFailures,
			Skipped:             c.Skipped,
			OpenEvents:          c.OpenEvents,
			Recoveries:          c.Recoveries,
			HalfOpenProbes:      c.HalfOpenProbes,
			LastSuccess:         c.LastSuccess,
			LastFailure:         c.LastFailure,
			LastError:           c.LastError,
		})
	}
	a.upstreamMu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].RawAddr != out[j].RawAddr {
			return out[i].RawAddr < out[j].RawAddr
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func (a *App) recordForwardPolicy(policy string, result string) {
	if policy == "" {
		policy = "default"
	}
	a.forwardPolicyMu.Lock()
	if a.forwardPolicyStats == nil {
		a.forwardPolicyStats = make(map[string]*forwardPolicyCounter)
	}
	counter := a.forwardPolicyStats[policy]
	if counter == nil {
		counter = &forwardPolicyCounter{}
		a.forwardPolicyStats[policy] = counter
	}
	switch result {
	case "selected":
		counter.Selected++
	case "success":
		counter.Success++
	case "dns_error":
		counter.DNSFailures++
	case "error":
		counter.Errors++
	}
	a.forwardPolicyMu.Unlock()
}

func (a *App) forwardPolicyViews(cfg *Config) []forwardPolicyView {
	wanted := map[string]struct{}{"default": {}}
	for _, zone := range cfg.ForwardZones {
		if len(zone.Upstreams) > 0 {
			wanted[zone.Domain] = struct{}{}
		}
	}

	a.forwardPolicyMu.Lock()
	out := make([]forwardPolicyView, 0, len(wanted))
	for policy := range wanted {
		view := forwardPolicyView{Policy: policy}
		if counter := a.forwardPolicyStats[policy]; counter != nil {
			view.Selected = counter.Selected
			view.Success = counter.Success
			view.DNSFailures = counter.DNSFailures
			view.Errors = counter.Errors
		}
		out = append(out, view)
	}
	a.forwardPolicyMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Policy == "default" {
			return true
		}
		if out[j].Policy == "default" {
			return false
		}
		return out[i].Policy < out[j].Policy
	})
	return out
}

func (a *App) forwardDNS(req *dns.Msg) (*dns.Msg, error) {
	cfg := a.getConfig()
	name := ""
	if req != nil && len(req.Question) > 0 {
		name = normalizeName(req.Question[0].Name)
	}
	return a.forwardDNSWithPolicy(req, forwardPolicyForName(name, cfg))
}

func (a *App) forwardDNSWithPolicy(req *dns.Msg, policy forwardPolicy) (*dns.Msg, error) {
	a.recordForwardPolicy(policy.Key, "selected")
	if len(policy.Upstreams) == 0 {
		a.recordForwardPolicy(policy.Key, "error")
		if policy.Domain != "" {
			return nil, fmt.Errorf("no upstreams configured for forward zone *.%s", policy.Domain)
		}
		return nil, fmt.Errorf("no default upstreams configured")
	}

	var attemptErrors []string
	var lastRetryableResponse *dns.Msg
	attempted := 0
	for _, target := range shuffledUpstreamTargets(policy.Upstreams) {
		configuredProto := canonicalUpstreamProto(target.Proto)
		proto, endpoint, err := resolveUpstream(target.Addr, configuredProto)
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", target.Addr, err))
			continue
		}

		attempt, allowed, remaining := a.beginUpstreamAttempt(target.Addr, configuredProto, proto)
		if !allowed {
			if remaining > 0 {
				attemptErrors = append(attemptErrors, fmt.Sprintf("%s[%s]: circuit open for %s", endpoint, proto, remaining.Truncate(time.Millisecond)))
			} else {
				attemptErrors = append(attemptErrors, fmt.Sprintf("%s[%s]: half-open probe already in flight", endpoint, proto))
			}
			continue
		}
		attempted++

		var resp *dns.Msg
		if proto == "https" {
			resp, err = a.exchangeDoH(req, endpoint)
		} else {
			resp, err = exchangeClassicDNS(req, proto, endpoint)
		}
		if err != nil {
			a.completeUpstreamFailure(attempt, err)
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s[%s]: %v", endpoint, proto, err))
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			a.completeUpstreamDNSFailure(attempt)
			lastRetryableResponse = resp
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s[%s]: DNS %s", endpoint, proto, dns.RcodeToString[resp.Rcode]))
			continue
		}
		a.completeUpstreamSuccess(attempt)
		a.recordForwardPolicy(policy.Key, "success")
		return resp, nil
	}

	if lastRetryableResponse != nil {
		a.recordForwardPolicy(policy.Key, "dns_error")
		return lastRetryableResponse, nil
	}
	a.recordForwardPolicy(policy.Key, "error")
	prefix := "default"
	if policy.Domain != "" {
		prefix = "*." + policy.Domain
	}
	if len(attemptErrors) == 0 {
		return nil, fmt.Errorf("forward policy %s has no usable upstreams", prefix)
	}
	if attempted == 0 {
		return nil, fmt.Errorf("all upstream circuits unavailable for policy %s: %s", prefix, strings.Join(attemptErrors, "; "))
	}
	return nil, fmt.Errorf("all attempted upstreams failed for policy %s: %s", prefix, strings.Join(attemptErrors, "; "))
}

func (a *App) logForwardError(name string, qtype uint16, err error) {
	const interval = 10 * time.Second
	now := time.Now()
	a.forwardLogMu.Lock()
	if !a.lastForwardErrorLog.IsZero() && now.Sub(a.lastForwardErrorLog) < interval {
		a.forwardErrorSuppressed++
		a.forwardLogMu.Unlock()
		return
	}
	suppressed := a.forwardErrorSuppressed
	a.forwardErrorSuppressed = 0
	a.lastForwardErrorLog = now
	a.forwardLogMu.Unlock()

	log.Printf(
		"FORWARD_ERROR name=%s qtype=%s suppressed=%d error=%v",
		name,
		dns.TypeToString[qtype],
		suppressed,
		err,
	)
}

func shuffledUpstreamTargets(upstreams []upstreamTarget) []upstreamTarget {
	res := append([]upstreamTarget(nil), upstreams...)
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
	parsed := normalizeRouteIP(net.ParseIP(ip))
	if parsed == nil {
		return ""
	}

	queryName := cymruQueryName(parsed)
	if queryName == "" {
		return ""
	}

	req := new(dns.Msg)
	req.SetQuestion(queryName, dns.TypeTXT)
	req.RecursionDesired = true

	cfg := a.getConfig()
	resp, err := a.forwardDNSWithPolicy(req, buildForwardPolicy("default", "", defaultUpstreamTargets(cfg)))
	if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
		return ""
	}

	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		if prefix := parseCymruPrefix(strings.Join(txt.Txt, ""), parsed); prefix != "" {
			return prefix
		}
	}
	return ""
}

func cymruQueryName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com.", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hex = "0123456789abcdef"
	labels := make([]byte, 0, 64+len("origin6.asn.cymru.com."))
	for i := len(v6) - 1; i >= 0; i-- {
		b := v6[i]
		labels = append(labels, hex[b&0x0f], '.', hex[b>>4], '.')
	}
	labels = append(labels, "origin6.asn.cymru.com."...)
	return string(labels)
}

func parseCymruPrefix(txt string, ip net.IP) string {
	fields := strings.Split(txt, "|")
	if len(fields) < 2 {
		return ""
	}
	prefix := strings.TrimSpace(fields[1])
	_, netw, err := net.ParseCIDR(prefix)
	if err != nil || netw == nil {
		return ""
	}

	if ip4 := ip.To4(); ip4 != nil {
		if netw.IP.To4() == nil || !netw.Contains(ip4) {
			return ""
		}
		ones, bits := netw.Mask.Size()
		if bits != 32 || ones >= 32 {
			return ""
		}
		return netw.String()
	}

	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil || netw.IP.To4() != nil || !netw.Contains(ip16) {
		return ""
	}
	ones, bits := netw.Mask.Size()
	if bits != 128 || ones >= 128 {
		return ""
	}
	return netw.String()
}

const maxUDPResponseSize = 1232

// writeDNSResponse returns a full response to TCP clients. For UDP clients it
// respects the EDNS0 advertised buffer size, defaults to 512 bytes without
// EDNS0, and caps the response at maxUDPResponseSize to avoid IP fragmentation.
// Msg.Truncate sets TC=1 when records have to be omitted, prompting the client
// to retry the same query over TCP.
func writeDNSResponse(w dns.ResponseWriter, req, resp *dns.Msg) error {
	if resp == nil {
		return fmt.Errorf("nil DNS response")
	}

	out := resp.Copy()
	if req != nil {
		out.Id = req.Id
	}

	if !isUDPResponseWriter(w) {
		out.Compress = true
		return w.WriteMsg(out)
	}

	udpSize := dns.MinMsgSize
	if req != nil {
		if opt := req.IsEdns0(); opt != nil {
			udpSize = int(opt.UDPSize())
			if udpSize < dns.MinMsgSize {
				udpSize = dns.MinMsgSize
			}
		}
	}
	if udpSize > maxUDPResponseSize {
		udpSize = maxUDPResponseSize
	}

	// If the response already contains OPT, advertise the limit actually used
	// by this server rather than forwarding the upstream server's buffer size.
	if opt := out.IsEdns0(); opt != nil {
		opt.SetUDPSize(uint16(udpSize))
	}

	out.Truncate(udpSize)
	// Truncate may turn compression off when the uncompressed response fits.
	// Re-enabling it can only make the final UDP payload smaller.
	out.Compress = true
	return w.WriteMsg(out)
}

func isUDPResponseWriter(w dns.ResponseWriter) bool {
	if w == nil {
		return false
	}
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		return true
	}
	if addr := w.LocalAddr(); addr != nil {
		return strings.HasPrefix(strings.ToLower(addr.Network()), "udp")
	}
	return false
}

func respondSERVFAIL(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	_ = writeDNSResponse(w, req, m)
}

func (a *App) resetConntrackForIP(ipString string) {
	ip := normalizeRouteIP(net.ParseIP(ipString))
	if ip == nil {
		atomic.AddUint64(&a.conntrackResetErrors, 1)
		log.Printf("CONNTRACK_RESET_ERROR ip=%q error=invalid_ip", ipString)
		return
	}

	familyName := "ipv6"
	family := netlink.InetFamily(syscall.AF_INET6)
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		familyName = "ipv4"
		family = netlink.InetFamily(syscall.AF_INET)
	}

	atomic.AddUint64(&a.conntrackResetAttempts, 1)
	deleted, err := netlink.ConntrackDeleteFilter(
		netlink.ConntrackTable,
		family,
		conntrackIPFilter{ip: ip},
	)
	if err != nil {
		atomic.AddUint64(&a.conntrackResetErrors, 1)
		log.Printf("CONNTRACK_RESET_ERROR ip=%s family=%s error=%v", ip.String(), familyName, err)
		return
	}

	atomic.AddUint64(&a.conntrackResetDeleted, uint64(deleted))
	if deleted > 0 {
		log.Printf("CONNTRACK_RESET ip=%s family=%s deleted=%d", ip.String(), familyName, deleted)
	}
}

func (a *App) addRoute(cidr string) error {
	cfg := a.getConfig()
	if cfg.WGInterface == "" {
		return fmt.Errorf("prepare route %s: wg_interface is empty", cidr)
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse route CIDR %q: %w", cidr, err)
	}
	link, err := netlink.LinkByName(cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("lookup interface %q for route %s: %w", cfg.WGInterface, cidr, err)
	}
	table := effectiveRouteTable(cfg.RouteTable)
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Table: table}
	if gw, ok, err := routeGatewayForCIDR(cfg, dst); err != nil {
		return fmt.Errorf("select gateway for route %s table %d dev %s: %w", cidr, table, cfg.WGInterface, err)
	} else if ok {
		route.Gw = gw
	}
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf(
			"netlink RouteReplace dst=%s table=%d dev=%s(index=%d) gw=%s: %w",
			cidr, table, cfg.WGInterface, link.Attrs().Index, routeGatewayString(route.Gw), err,
		)
	}
	return nil
}

func routeGatewayString(gw net.IP) string {
	if gw == nil {
		return "<direct>"
	}
	return gw.String()
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

func (a *App) recordRouteAddError(ip, cidr string, routeErr, reloadErr error, recovered bool) {
	cfg := a.getConfig()
	diag := routeErrorDiagnostic{
		Time:                    time.Now().Format(time.RFC3339Nano),
		IP:                      ip,
		CIDR:                    cidr,
		Table:                   effectiveRouteTable(cfg.RouteTable),
		Interface:               cfg.WGInterface,
		Error:                   routeErr.Error(),
		ErrorType:               fmt.Sprintf("%T", routeErr),
		RoutePresentAfterReload: recovered,
	}
	if reloadErr != nil {
		diag.SnapshotReloadError = reloadErr.Error()
	}

	var errno syscall.Errno
	if errors.As(routeErr, &errno) {
		diag.Errno = int(errno)
		diag.ErrnoText = errno.Error()
	}

	parsed := normalizeRouteIP(net.ParseIP(ip))
	if parsed == nil {
		if _, dst, err := net.ParseCIDR(cidr); err == nil {
			parsed = normalizeRouteIP(dst.IP)
		}
	}
	if parsed != nil && parsed.To4() != nil {
		diag.Family = "ipv4"
	} else if parsed != nil {
		diag.Family = "ipv6"
	} else {
		diag.Family = "unknown"
	}

	_, dst, dstErr := net.ParseCIDR(cidr)
	if dstErr == nil {
		if gw, ok, gwErr := routeGatewayForCIDR(cfg, dst); gwErr != nil {
			diag.Gateway = "config error: " + gwErr.Error()
		} else if ok {
			diag.Gateway = gw.String()
		} else {
			diag.Gateway = "<direct>"
		}
	}

	var link netlink.Link
	if cfg.WGInterface != "" {
		var err error
		link, err = netlink.LinkByName(cfg.WGInterface)
		if err != nil {
			diag.LinkLookupError = err.Error()
		} else if attrs := link.Attrs(); attrs != nil {
			diag.LinkIndex = attrs.Index
			diag.LinkType = link.Type()
			diag.LinkFlags = attrs.Flags.String()
			diag.LinkOperState = fmt.Sprint(attrs.OperState)

			family := netlink.FAMILY_ALL
			if parsed != nil && parsed.To4() != nil {
				family = netlink.FAMILY_V4
			} else if parsed != nil {
				family = netlink.FAMILY_V6
			}
			addrs, addrErr := netlink.AddrList(link, family)
			if addrErr != nil {
				diag.AddressListError = addrErr.Error()
			} else {
				for _, addr := range addrs {
					diag.InterfaceAddresses = append(diag.InterfaceAddresses, addr.String())
				}
			}
		}
	}

	if parsed != nil {
		family := netlink.FAMILY_V6
		if parsed.To4() != nil {
			family = netlink.FAMILY_V4
		}
		filter := &netlink.Route{Table: diag.Table}
		routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_TABLE)
		if err != nil {
			diag.RouteListError = err.Error()
		} else {
			diag.DestinationRoutes = relevantRouteDescriptions(routes, parsed, 16)
			if gw := net.ParseIP(diag.Gateway); gw != nil {
				diag.GatewayRoutes = relevantRouteDescriptions(routes, gw, 16)
			}
		}
	}

	a.routeErrMu.Lock()
	if len(a.routeErrorLog) >= routeErrorHistoryLen {
		copy(a.routeErrorLog, a.routeErrorLog[len(a.routeErrorLog)-routeErrorHistoryLen+1:])
		a.routeErrorLog = a.routeErrorLog[:routeErrorHistoryLen-1]
	}
	a.routeErrorLog = append(a.routeErrorLog, diag)
	a.routeErrMu.Unlock()

	if encoded, err := json.Marshal(diag); err == nil {
		log.Printf("ROUTE_ADD_ERROR %s", encoded)
	} else {
		log.Printf("ROUTE_ADD_ERROR ip=%s cidr=%s err=%v diagnostic_marshal_error=%v", ip, cidr, routeErr, err)
	}
}

func relevantRouteDescriptions(routes []netlink.Route, ip net.IP, limit int) []string {
	if ip == nil || limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	for _, route := range routes {
		if route.Dst != nil && !route.Dst.Contains(ip) {
			continue
		}
		out = append(out, formatRouteDiagnostic(route))
		if len(out) >= limit {
			break
		}
	}
	return out
}

func formatRouteDiagnostic(route netlink.Route) string {
	dst := "default"
	if route.Dst != nil {
		dst = route.Dst.String()
	}
	return fmt.Sprintf(
		"dst=%s gw=%s link_index=%d table=%d scope=%v protocol=%v priority=%d flags=%d",
		dst, routeGatewayString(route.Gw), route.LinkIndex, route.Table, route.Scope, route.Protocol, route.Priority, route.Flags,
	)
}

func formatWebTime(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	return value.Format(time.RFC3339)
}

func (a *App) upstreamSnapshotMap() map[string]upstreamCircuitSnapshot {
	snapshots := a.upstreamCircuitSnapshots()
	out := make(map[string]upstreamCircuitSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		out[upstreamCircuitKey(snapshot.RawAddr, snapshot.ConfiguredProto)] = snapshot
	}
	return out
}

func upstreamTargetScopes(cfg *Config) map[string][]string {
	out := make(map[string][]string)
	add := func(target upstreamTarget, scope string) {
		key := upstreamCircuitKey(target.Addr, target.Proto)
		for _, existing := range out[key] {
			if existing == scope {
				return
			}
		}
		out[key] = append(out[key], scope)
	}
	for _, target := range defaultUpstreamTargets(cfg) {
		add(target, "default")
	}
	for _, zone := range cfg.ForwardZones {
		for _, upstream := range zone.Upstreams {
			add(upstreamTarget{Addr: upstream.Addr, Proto: upstream.Proto}, "*."+zone.Domain)
		}
	}
	for key := range out {
		sort.Strings(out[key])
	}
	return out
}

func (a *App) upstreamViewForTarget(target upstreamTarget, scopes []string, snapshots map[string]upstreamCircuitSnapshot) upstreamView {
	configuredProto := canonicalUpstreamProto(target.Proto)
	if configuredProto == "" {
		configuredProto = "auto"
	}
	proto, endpoint, resolveErr := resolveUpstream(target.Addr, configuredProto)
	if resolveErr != nil {
		proto = configuredProto
		endpoint = "invalid: " + resolveErr.Error()
	}
	view := upstreamView{
		Addr:            target.Addr,
		ConfiguredProto: configuredProto,
		Scopes:          strings.Join(scopes, ", "),
		Proto:           proto,
		Endpoint:        endpoint,
		State:           string(upstreamCircuitClosed),
		OpenRemaining:   "—",
		LastSuccess:     "—",
		LastFailure:     "—",
	}
	if snapshot, ok := snapshots[upstreamCircuitKey(target.Addr, configuredProto)]; ok {
		view.State = string(snapshot.State)
		view.ConsecutiveFailures = snapshot.ConsecutiveFailures
		view.Successes = snapshot.Successes
		view.Failures = snapshot.Failures
		view.DNSFailures = snapshot.DNSFailures
		view.Skipped = snapshot.Skipped
		view.OpenEvents = snapshot.OpenEvents
		view.Recoveries = snapshot.Recoveries
		view.HalfOpenProbes = snapshot.HalfOpenProbes
		view.LastSuccess = formatWebTime(snapshot.LastSuccess)
		view.LastFailure = formatWebTime(snapshot.LastFailure)
		view.LastError = snapshot.LastError
		if snapshot.State == upstreamCircuitOpen && snapshot.OpenUntil.After(time.Now()) {
			view.OpenRemaining = time.Until(snapshot.OpenUntil).Truncate(time.Second).String()
		}
	}
	return view
}

func (a *App) defaultUpstreamViews(cfg *Config) []upstreamView {
	snapshots := a.upstreamSnapshotMap()
	out := make([]upstreamView, 0, len(cfg.Upstreams))
	for _, target := range defaultUpstreamTargets(cfg) {
		out = append(out, a.upstreamViewForTarget(target, []string{"default"}, snapshots))
	}
	return out
}

func (a *App) forwardZoneViews(cfg *Config) []forwardZoneView {
	snapshots := a.upstreamSnapshotMap()
	out := make([]forwardZoneView, 0, len(cfg.ForwardZones))
	for _, zone := range cfg.ForwardZones {
		view := forwardZoneView{ID: zone.ID, Domain: zone.Domain, Pattern: "*." + zone.Domain}
		for _, upstream := range zone.Upstreams {
			target := upstreamTarget{Addr: upstream.Addr, Proto: upstream.Proto}
			view.Upstreams = append(view.Upstreams, forwardZoneUpstreamView{
				ID:   upstream.ID,
				View: a.upstreamViewForTarget(target, []string{"*." + zone.Domain}, snapshots),
			})
		}
		out = append(out, view)
	}
	return out
}

func (a *App) upstreamViews(cfg *Config) []upstreamView {
	snapshots := a.upstreamSnapshotMap()
	scopes := upstreamTargetScopes(cfg)
	targets := allConfiguredUpstreamTargets(cfg)
	out := make([]upstreamView, 0, len(targets))
	for _, target := range targets {
		out = append(out, a.upstreamViewForTarget(target, scopes[upstreamCircuitKey(target.Addr, target.Proto)], snapshots))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].ConfiguredProto < out[j].ConfiguredProto
	})
	return out
}

func (a *App) statsSnapshot() statsData {
	cfg := a.getConfig()
	a.cacheMu.RLock()
	cacheEntries := len(a.cache)
	a.cacheMu.RUnlock()
	a.srvMu.Lock()
	activeListeners := len(a.servers)
	pendingListeners := len(a.pendingListeners)
	a.srvMu.Unlock()
	listenerStates := a.listenerViews()
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
		Uptime:           time.Since(a.startedAt).Truncate(time.Second).String(),
		StartedAt:        a.startedAt.Format(time.RFC3339),
		CacheEntries:     cacheEntries,
		ActiveListeners:  activeListeners,
		PendingListeners: pendingListeners,
		ListenAddrs:      len(cfg.ListenAddrs), Upstreams: len(cfg.Upstreams), ForwardZones: len(cfg.ForwardZones), ForwardUpstreams: forwardZoneUpstreamCount(cfg), SpecialDomains: len(cfg.SpecialDomains),
		LocalADomains: len(cfg.LocalA), LocalAAAADomains: len(cfg.LocalAAAA), LookupCIDR: cfg.LookupCIDR,
		ReplyBeforeRoute: cfg.ReplyBeforeRoute, ListenerFreeBind: cfg.ListenerFreeBind, RouteIPv4: cfg.RouteIPv4, RouteIPv6: cfg.RouteIPv6, RouteTable: cfg.RouteTable, WGInterface: cfg.WGInterface, WGGateway: cfg.WGGateway, WGGatewayV4: cfg.WGGatewayV4, WGGatewayV6: cfg.WGGatewayV6,
		RouteSnapshot: routeSnapshot, IPCacheEntries: ipEntries, CIDRCacheEntries: cidrEntries,
		TotalQueries: atomic.LoadUint64(&a.totalQueries), CacheHits: atomic.LoadUint64(&a.cacheHits), CacheMisses: atomic.LoadUint64(&a.cacheMisses),
		LocalAnswers: atomic.LoadUint64(&a.localAnswers), ForwardedOK: atomic.LoadUint64(&a.forwardedOK), ServfailCount: atomic.LoadUint64(&a.servfailCount),
		RouteAdds: atomic.LoadUint64(&a.routeAdds), RouteAddErrors: atomic.LoadUint64(&a.routeAddErrors), ForwardErrors: atomic.LoadUint64(&a.forwardErrors),
		LookupCIDRAttempts: atomic.LoadUint64(&a.lookupCIDRAttempts), LookupCIDRFailed: atomic.LoadUint64(&a.lookupCIDRFailed), RouteQueueDrops: atomic.LoadUint64(&a.routeQueueDrops),
		ConntrackResetAttempts: atomic.LoadUint64(&a.conntrackResetAttempts), ConntrackResetDeleted: atomic.LoadUint64(&a.conntrackResetDeleted), ConntrackResetErrors: atomic.LoadUint64(&a.conntrackResetErrors),
		ListenerBindAttempts: atomic.LoadUint64(&a.listenerBindAttempts), ListenerBindErrors: atomic.LoadUint64(&a.listenerBindErrors), ListenerStarts: atomic.LoadUint64(&a.listenerStarts), ListenerRecoveries: atomic.LoadUint64(&a.listenerRecoveries),
		UpstreamCircuits: a.upstreamViews(cfg),
		ForwardPolicies:  a.forwardPolicyViews(cfg),
		ListenerStates:   listenerStates,
	}
}

func prometheusLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return v
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
	gauge("dns_route_pending_listeners", s.PendingListeners, "number of listeners waiting for a successful bind")
	gauge("dns_route_listener_freebind_enabled", boolToInt(s.ListenerFreeBind), "IP_FREEBIND/IPV6_FREEBIND enabled for newly created listeners")
	gauge("dns_route_listener_retry_interval_seconds", int64(listenerRetryInterval.Seconds()), "listener bind retry interval in seconds")
	gauge("dns_route_listen_addrs", s.ListenAddrs, "number of configured listen addresses")
	gauge("dns_route_upstreams", s.Upstreams, "number of configured default upstreams")
	gauge("dns_route_forward_zones", s.ForwardZones, "number of configured conditional forwarding zones")
	gauge("dns_route_forward_zone_upstreams", s.ForwardUpstreams, "number of upstream entries assigned to conditional forwarding zones")
	gauge("dns_route_special_domains", s.SpecialDomains, "number of special domains")
	gauge("dns_route_local_a_domains", s.LocalADomains, "number of local A domains")
	gauge("dns_route_local_aaaa_domains", s.LocalAAAADomains, "number of local AAAA domains")
	gauge("dns_route_lookup_cidr_enabled", boolToInt(s.LookupCIDR), "Team Cymru BGP prefix lookup enabled; legacy metric name")
	gauge("dns_route_reply_before_route_enabled", boolToInt(s.ReplyBeforeRoute), "reply before route enabled")
	gauge("dns_route_route_ipv4_enabled", boolToInt(s.RouteIPv4), "IPv4 route programming enabled")
	gauge("dns_route_route_ipv6_enabled", boolToInt(s.RouteIPv6), "IPv6 route programming enabled")
	gauge("dns_route_route_table", s.RouteTable, "configured route table")
	gauge("dns_route_route_snapshot_entries", s.RouteSnapshot, "route snapshot entries")
	gauge("dns_route_route_ip_cache_entries", s.IPCacheEntries, "route manager IP cache entries")
	gauge("dns_route_route_cidr_cache_entries", s.CIDRCacheEntries, "route manager prefix cache entries; legacy metric name")
	counter("dns_route_queries_total", s.TotalQueries, "total DNS queries")
	counter("dns_route_cache_hits_total", s.CacheHits, "cache hits")
	counter("dns_route_cache_misses_total", s.CacheMisses, "cache misses")
	counter("dns_route_local_answers_total", s.LocalAnswers, "local answers")
	counter("dns_route_forwarded_ok_total", s.ForwardedOK, "successful forwarded answers")
	counter("dns_route_servfail_total", s.ServfailCount, "servfail responses")
	counter("dns_route_route_add_total", s.RouteAdds, "successful route additions")
	counter("dns_route_route_add_errors_total", s.RouteAddErrors, "route add errors")
	counter("dns_route_route_queue_drops_total", s.RouteQueueDrops, "route requests dropped because the route worker queue was full")
	counter("dns_route_conntrack_reset_attempts_total", s.ConntrackResetAttempts, "conntrack reset attempts after an early DNS reply and route installation")
	counter("dns_route_conntrack_reset_deleted_total", s.ConntrackResetDeleted, "conntrack flows deleted after destination route installation")
	counter("dns_route_conntrack_reset_errors_total", s.ConntrackResetErrors, "conntrack reset errors")
	counter("dns_route_listener_bind_attempts_total", s.ListenerBindAttempts, "listener socket bind attempts")
	counter("dns_route_listener_bind_errors_total", s.ListenerBindErrors, "listener socket bind errors")
	counter("dns_route_listener_starts_total", s.ListenerStarts, "listeners successfully started")
	counter("dns_route_listener_recoveries_total", s.ListenerRecoveries, "pending listeners that later started successfully")
	counter("dns_route_forward_errors_total", s.ForwardErrors, "forward errors")
	fmt.Fprintf(w, "# HELP dns_route_lookup_cidr_total Team Cymru BGP prefix lookup counters; legacy metric name\n# TYPE dns_route_lookup_cidr_total counter\n")
	fmt.Fprintf(w, "dns_route_lookup_cidr_total{result=\"attempts\"} %d\n", s.LookupCIDRAttempts)
	fmt.Fprintf(w, "dns_route_lookup_cidr_total{result=\"failed\"} %d\n", s.LookupCIDRFailed)

	fmt.Fprintln(w, "# HELP dns_route_listener_state Current listener state as a one-hot gauge")
	fmt.Fprintln(w, "# TYPE dns_route_listener_state gauge")
	fmt.Fprintln(w, "# HELP dns_route_listener_pending_attempts Number of failed bind attempts for a pending listener")
	fmt.Fprintln(w, "# TYPE dns_route_listener_pending_attempts gauge")
	for _, listener := range s.ListenerStates {
		labels := fmt.Sprintf(
			"network=\"%s\",addr=\"%s\",freebind=\"%t\"",
			prometheusLabelValue(listener.Net),
			prometheusLabelValue(listener.Addr),
			listener.FreeBind,
		)
		for _, state := range []string{"active", "pending"} {
			value := 0
			if listener.State == state {
				value = 1
			}
			fmt.Fprintf(w, "dns_route_listener_state{%s,state=\"%s\"} %d\n", labels, state, value)
		}
		fmt.Fprintf(w, "dns_route_listener_pending_attempts{%s} %d\n", labels, listener.Attempts)
	}

	fmt.Fprintln(w, "# HELP dns_route_forward_policy_selected_total Cache-miss queries forwarded through each outbound policy")
	fmt.Fprintln(w, "# TYPE dns_route_forward_policy_selected_total counter")
	fmt.Fprintln(w, "# HELP dns_route_forward_policy_results_total Forwarding results for each outbound policy")
	fmt.Fprintln(w, "# TYPE dns_route_forward_policy_results_total counter")
	for _, policy := range s.ForwardPolicies {
		label := prometheusLabelValue(policy.Policy)
		fmt.Fprintf(w, "dns_route_forward_policy_selected_total{policy=\"%s\"} %d\n", label, policy.Selected)
		fmt.Fprintf(w, "dns_route_forward_policy_results_total{policy=\"%s\",result=\"success\"} %d\n", label, policy.Success)
		fmt.Fprintf(w, "dns_route_forward_policy_results_total{policy=\"%s\",result=\"dns_error\"} %d\n", label, policy.DNSFailures)
		fmt.Fprintf(w, "dns_route_forward_policy_results_total{policy=\"%s\",result=\"error\"} %d\n", label, policy.Errors)
	}

	gauge("dns_route_upstream_circuit_failure_threshold", upstreamFailureThreshold, "consecutive upstream failures required to open a circuit")
	gauge("dns_route_upstream_circuit_base_backoff_seconds", int64(upstreamCircuitBaseBackoff.Seconds()), "initial upstream circuit cooldown in seconds")
	gauge("dns_route_upstream_circuit_max_backoff_seconds", int64(upstreamCircuitMaxBackoff.Seconds()), "maximum upstream circuit cooldown in seconds")

	fmt.Fprintln(w, "# HELP dns_route_upstream_circuit_state Current upstream circuit state as a one-hot gauge")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_circuit_state gauge")
	fmt.Fprintln(w, "# HELP dns_route_upstream_circuit_consecutive_failures Consecutive failures in the current circuit generation")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_circuit_consecutive_failures gauge")
	fmt.Fprintln(w, "# HELP dns_route_upstream_circuit_open_until_seconds Unix timestamp until which the upstream circuit remains open")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_circuit_open_until_seconds gauge")
	fmt.Fprintln(w, "# HELP dns_route_upstream_circuit_open_remaining_seconds Remaining upstream circuit cooldown in seconds")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_circuit_open_remaining_seconds gauge")
	fmt.Fprintln(w, "# HELP dns_route_upstream_requests_total Actual network requests sent to each upstream by result")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_requests_total counter")
	fmt.Fprintln(w, "# HELP dns_route_upstream_circuit_skipped_total Requests that skipped an upstream because its circuit was open or probing")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_circuit_skipped_total counter")
	fmt.Fprintln(w, "# HELP dns_route_upstream_circuit_open_total Number of times an upstream circuit opened")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_circuit_open_total counter")
	fmt.Fprintln(w, "# HELP dns_route_upstream_circuit_recoveries_total Successful half-open probes that closed an upstream circuit")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_circuit_recoveries_total counter")
	fmt.Fprintln(w, "# HELP dns_route_upstream_circuit_half_open_probes_total Half-open probe requests admitted for an upstream")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_circuit_half_open_probes_total counter")
	fmt.Fprintln(w, "# HELP dns_route_upstream_last_success_timestamp_seconds Unix timestamp of the last successful upstream request")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_last_success_timestamp_seconds gauge")
	fmt.Fprintln(w, "# HELP dns_route_upstream_last_failure_timestamp_seconds Unix timestamp of the last failed upstream request")
	fmt.Fprintln(w, "# TYPE dns_route_upstream_last_failure_timestamp_seconds gauge")

	now := time.Now()
	for _, upstream := range a.upstreamCircuitSnapshots() {
		labels := fmt.Sprintf("upstream=\"%s\",proto=\"%s\"", prometheusLabelValue(upstream.RawAddr), prometheusLabelValue(upstream.Proto))
		for _, state := range []upstreamCircuitState{upstreamCircuitClosed, upstreamCircuitOpen, upstreamCircuitHalfOpen} {
			value := 0
			if upstream.State == state {
				value = 1
			}
			fmt.Fprintf(w, "dns_route_upstream_circuit_state{%s,state=\"%s\"} %d\n", labels, state, value)
		}
		openUntil := int64(0)
		remaining := float64(0)
		if !upstream.OpenUntil.IsZero() {
			openUntil = upstream.OpenUntil.Unix()
			if upstream.OpenUntil.After(now) {
				remaining = upstream.OpenUntil.Sub(now).Seconds()
			}
		}
		lastSuccess := int64(0)
		if !upstream.LastSuccess.IsZero() {
			lastSuccess = upstream.LastSuccess.Unix()
		}
		lastFailure := int64(0)
		if !upstream.LastFailure.IsZero() {
			lastFailure = upstream.LastFailure.Unix()
		}
		fmt.Fprintf(w, "dns_route_upstream_circuit_consecutive_failures{%s} %d\n", labels, upstream.ConsecutiveFailures)
		fmt.Fprintf(w, "dns_route_upstream_circuit_open_until_seconds{%s} %d\n", labels, openUntil)
		fmt.Fprintf(w, "dns_route_upstream_circuit_open_remaining_seconds{%s} %.3f\n", labels, remaining)
		fmt.Fprintf(w, "dns_route_upstream_requests_total{%s,result=\"success\"} %d\n", labels, upstream.Successes)
		fmt.Fprintf(w, "dns_route_upstream_requests_total{%s,result=\"error\"} %d\n", labels, upstream.Failures)
		fmt.Fprintf(w, "dns_route_upstream_requests_total{%s,result=\"dns_error\"} %d\n", labels, upstream.DNSFailures)
		fmt.Fprintf(w, "dns_route_upstream_circuit_skipped_total{%s} %d\n", labels, upstream.Skipped)
		fmt.Fprintf(w, "dns_route_upstream_circuit_open_total{%s} %d\n", labels, upstream.OpenEvents)
		fmt.Fprintf(w, "dns_route_upstream_circuit_recoveries_total{%s} %d\n", labels, upstream.Recoveries)
		fmt.Fprintf(w, "dns_route_upstream_circuit_half_open_probes_total{%s} %d\n", labels, upstream.HalfOpenProbes)
		fmt.Fprintf(w, "dns_route_upstream_last_success_timestamp_seconds{%s} %d\n", labels, lastSuccess)
		fmt.Fprintf(w, "dns_route_upstream_last_failure_timestamp_seconds{%s} %d\n", labels, lastFailure)
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
