package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
        "strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
)

const (
	cacheCleanupInterval = time.Minute // период чистки устаревших записей
	whoisPort            = "43"        // порт WHOIS
	wgInterface          = "wg0"       // имя VPN-интерфейса
)

var (
	listenAddrs    []string
	upstreams      []string
	wgGateway      string
	specialDomains []string
        routeTable     int // по умолчанию = 0 (main)

	cache   = make(map[string]cacheEntry)
	cacheMu sync.RWMutex

	cidrRe = regexp.MustCompile(`(?mi)^CIDR:\s*([0-9./]+)`)
)

type cacheEntry struct {
	msg        *dns.Msg
	expiration time.Time
}

func init() {
	// Читаем обязательные переменные окружения
	// LISTEN_ADDRS: список IP для прослушивания, разделитель запятая
	if env := os.Getenv("LISTEN_ADDRS"); env != "" {
		for _, a := range strings.Split(env, ",") {
			if addr := strings.TrimSpace(a); addr != "" {
				listenAddrs = append(listenAddrs, addr)
			}
		}
	}
        if env := os.Getenv("UPSTREAM"); env != "" {
                for _, u := range strings.Split(env, ",") {
			if up := strings.TrimSpace(u); up != "" {
				upstreams = append(upstreams, up)
			}
		}
	}

	wgGateway = os.Getenv("WG_GATEWAY")

	if len(listenAddrs) == 0 || len(upstreams) == 0 || wgGateway == "" {
		log.Fatal("Необходимы env: LISTEN_ADDRS, UPSTREAM, WG_GATEWAY")
	}

	log.Printf("CONFIG: LISTEN_ADDRS=%v, UPSTREAMS=%v, WG_GATEWAY=%s", listenAddrs, upstreams, wgGateway)

	rand.Seed(time.Now().UnixNano())

	// Читаем список доменов
	if env := os.Getenv("DOMAINS"); env != "" {
		for _, d := range strings.Split(env, ",") {
			if dom := strings.ToLower(strings.TrimSpace(d)); dom != "" {
				specialDomains = append(specialDomains, dom)
			}
		}
	}
	if len(specialDomains) == 0 {
		log.Fatal("env DOMAINS не установлена или пуста (пример: DOMAINS=example.com,foo.bar)")
	}
	log.Printf("Loaded %d special domains", len(specialDomains))

        routeTableStr := os.Getenv("ROUTE_TABLE")
	if routeTableStr != "" {
                v, err := strconv.Atoi(routeTableStr)
		if err != nil {
			log.Fatalf("Некорректный ROUTE_TABLE=%q: %v", routeTableStr, err)
		}
		routeTable = v
		log.Printf("Using custom route table: %d", routeTable)
	} else {
		routeTable = 0 // main table
		log.Printf("ROUTE_TABLE not set, using main table")
	}

	// Фоновая чистка кэша
	go func() {
		ticker := time.NewTicker(cacheCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			cacheMu.Lock()
			for k, e := range cache {
				if now.After(e.expiration) {
					delete(cache, k)
				}
			}
			cacheMu.Unlock()
		}
	}()
}

func main() {
	dns.HandleFunc(".", handleDNS)

	// Start UDP and TCP servers on each address
	for _, addr := range listenAddrs {
		go startServer("udp", addr)
		go startServer("tcp", addr)
	}

	// Блокируем главный поток
	select {}
}

// startServer запускает DNS-сервер на указанном протоколе и адресе
func startServer(network, addr string) {
	srv := &dns.Server{Net: network, Addr: addr}
	log.Printf("Starting %s on %s", network, addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("%s ListenAndServe error: %v", network, err)
	}
}

func shuffledUpstreams() []string {
	res := append([]string(nil), upstreams...)
	rand.Shuffle(len(res), func(i, j int) {
		res[i], res[j] = res[j], res[i]
	})
	return res
}

func forwardDNS(req *dns.Msg) (*dns.Msg, error) {
	var lastErr error

	for _, upstream := range shuffledUpstreams() {
		var resp *dns.Msg
		var err error

		if strings.HasPrefix(upstream, "https://") {
			wire, errPack := req.Pack()
			if errPack != nil {
				lastErr = errPack
				log.Printf("DoH pack error for %s: %v", upstream, errPack)
				continue
			}

			httpReq, errReq := http.NewRequest("POST", upstream, bytes.NewReader(wire))
			if errReq != nil {
				lastErr = errReq
				log.Printf("DoH request build error for %s: %v", upstream, errReq)
				continue
			}

			httpReq.Header.Set("Content-Type", "application/dns-message")
			httpReq.Header.Set("Accept", "application/dns-message")

			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}

			httpResp, errDoH := client.Do(httpReq)
			if errDoH != nil {
				lastErr = errDoH
				log.Printf("DoH forward via %s error: %v", upstream, errDoH)
				continue
			}

			body, errRead := io.ReadAll(httpResp.Body)
			httpResp.Body.Close()
			if errRead != nil {
				lastErr = errRead
				log.Printf("DoH read via %s error: %v", upstream, errRead)
				continue
			}

			if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
				lastErr = fmt.Errorf("unexpected HTTP status %s", httpResp.Status)
				log.Printf("DoH upstream %s returned %s", upstream, httpResp.Status)
				continue
			}

			resp = new(dns.Msg)
			if err = resp.Unpack(body); err != nil {
				lastErr = err
				log.Printf("DoH unpack via %s error: %v", upstream, err)
				continue
			}
		} else {
			client := &dns.Client{
				Net:       "tcp-tls",
				Timeout:   5 * time.Second,
				TLSConfig: &tls.Config{InsecureSkipVerify: true},
			}

			resp, _, err = client.Exchange(req, upstream)
			if err != nil {
				lastErr = err
				log.Printf("DNS forward via %s error: %v", upstream, err)
				continue
			}
		}

		log.Printf("DNS forward success via %s", upstream)
		return resp, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no upstreams configured")
	}
	return nil, lastErr
}

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		respondSERVFAIL(w, req)
		return
	}

	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	key := name + ":" + dns.TypeToString[q.Qtype]

	cacheMu.RLock()
	if entry, ok := cache[key]; ok && time.Now().Before(entry.expiration) {
		cacheMu.RUnlock()
		cached := entry.msg.Copy()
		cached.Id = req.Id
		w.WriteMsg(cached)
		return
	}
	cacheMu.RUnlock()

	resp, err := forwardDNS(req)
	if err != nil {
		log.Printf("Forward %s %s failed on all upstreams: %v", q.Name, dns.TypeToString[q.Qtype], err)
		respondSERVFAIL(w, req)
		return
	}

	resp.Id = req.Id

	if q.Qtype == dns.TypeA && isSpecial(name) {
		seen := make(map[string]struct{})
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				cidr := lookupCIDR(a.A.String())
				if cidr == "" {
					cidr = a.A.String() + "/32"
				}
				if _, found := seen[cidr]; !found {
					if err := addRoute(cidr); err != nil {
						log.Printf("Route add %s error: %v", cidr, err)
					} else {
						log.Printf("Route added: %s → dev %s via %s", cidr, wgInterface, wgGateway)
					}
					seen[cidr] = struct{}{}
				}
			}
		}
	}

	if len(resp.Answer) > 0 {
		minTTL := resp.Answer[0].Header().Ttl
		for _, rr := range resp.Answer[1:] {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}

		cacheMu.Lock()
		cache[key] = cacheEntry{
			msg:        resp.Copy(),
			expiration: time.Now().Add(time.Duration(minTTL) * time.Second),
		}
		cacheMu.Unlock()
	}

	w.WriteMsg(resp)
}

func isSpecial(name string) bool {
	for _, d := range specialDomains {
		// match exact domain or any subdomain
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// lookupCIDR: выбирает наиболее специфичную подсеть из WHOIS
func lookupCIDR(ip string) string {
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
	matches := cidrRe.FindAllSubmatch(combined, -1)
	var bestNet *net.IPNet
	bestOnes := -1
	for _, m := range matches {
		cidrStr := string(m[1])
		_, netw, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		ones, _ := netw.Mask.Size()
		if ones > bestOnes {
			bestOnes = ones
			bestNet = netw
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
	reader := bufio.NewReader(conn)
	_, err = io.Copy(&buf, reader)
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
	w.WriteMsg(m)
}

func addRoute(cidr string) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", cidr, err)
	}

	link, err := netlink.LinkByName(wgInterface)
	if err != nil {
		return fmt.Errorf("get link %q: %w", wgInterface, err)
	}

	gw := net.ParseIP(wgGateway)
	if gw == nil {
		return fmt.Errorf("invalid WG_GATEWAY %q", wgGateway)
	}

	route := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
		Table:     routeTable, // 0 = main table
	}

	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("route replace %q in table %d: %w", cidr, routeTable, err)
	}

	tableForLog := routeTable
	if tableForLog == 0 {
		tableForLog = 254
	}

	log.Printf("Route added: %s -> dev %s via %s table %d",
		cidr, wgInterface, wgGateway, tableForLog)

	return nil
}
