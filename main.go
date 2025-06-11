package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
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
	listenAddr     string
	upstream       string
	wgGateway      string
	specialDomains []string

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
	listenAddr = os.Getenv("LISTEN_ADDR")
	upstream = os.Getenv("UPSTREAM")
	wgGateway = os.Getenv("WG_GATEWAY")
	if listenAddr == "" || upstream == "" || wgGateway == "" {
		log.Fatal("Необходимы env: LISTEN_ADDR, UPSTREAM, WG_GATEWAY")
	}
	log.Printf("CONFIG: LISTEN_ADDR=%s UPSTREAM=%s WG_GATEWAY=%s", listenAddr, upstream, wgGateway)

	// Читаем список доменов
	env := os.Getenv("DOMAINS")
	if env == "" {
		log.Fatal("env DOMAINS не установлена (пример: DOMAINS=example.com,foo.bar)")
	}
	for _, d := range strings.Split(env, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			specialDomains = append(specialDomains, d)
		}
	}
	log.Printf("Loaded %d special domains", len(specialDomains))

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

	// UDP-сервер
	go func() {
		srv := &dns.Server{Addr: listenAddr, Net: "udp"}
		log.Printf("Starting UDP on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("UDP ListenAndServe error: %v", err)
		}
	}()

	// TCP-сервер
	srv := &dns.Server{Addr: listenAddr, Net: "tcp"}
	log.Printf("Starting TCP on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("TCP ListenAndServe error: %v", err)
	}
}

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		respondSERVFAIL(w, req)
		return
	}

	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	key := name + ":" + dns.TypeToString[q.Qtype]

	// Попытка из кеша
	cacheMu.RLock()
	if entry, ok := cache[key]; ok && time.Now().Before(entry.expiration) {
		cacheMu.RUnlock()
		w.WriteMsg(entry.msg.Copy())
		return
	}
	cacheMu.RUnlock()

	// Форвардим к upstream по TLS
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	resp, _, err := client.Exchange(req, upstream)
	if err != nil {
		log.Printf("Forward %s %s error: %v", q.Name, dns.TypeToString[q.Qtype], err)
		respondSERVFAIL(w, req)
		return
	}

	// Если A-запрос и специальный домен — добавляем маршруты подсетей
	if q.Qtype == dns.TypeA && isSpecial(name) {
		seen := map[string]struct{}{}
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				cidr := lookupCIDR(a.A.String())
				if cidr == "" {
					cidr = a.A.String() + "/32"
				}
				if _, exists := seen[cidr]; !exists {
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

	// Сохраняем в кеш по минимальному TTL
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
		if name == d {
			return true
		}
	}
	return false
}

// lookupCIDR: выбирает самую маленькую (самую специфичную) подсеть из WHOIS
func lookupCIDR(ip string) string {
	// 1) Запрос IANA
	data, err := whoisQuery("whois.iana.org:"+whoisPort, ip)
	if err != nil {
		return ""
	}
	refer := parseField(data, `(?mi)^refer:\s*(\S+)`)

	combined := data
	// 2) Региональный WHOIS, если refer задан
	if refer != "" {
		if data2, err2 := whoisQuery(refer+":"+whoisPort, ip); err2 == nil {
			combined = append(combined, data2...)
		}
	}

	// 3) Ищем все CIDR записи и выбираем с наибольшим префиксом (самая мелкая подсеть)
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
	// Парсим подсеть
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	gw := net.ParseIP(wgGateway)
	if gw == nil {
		return fmt.Errorf("invalid gateway IP: %s", wgGateway)
	}

	// Получаем link wg0
	link, err := netlink.LinkByName(wgInterface)
	if err != nil {
		return err
	}

	// Проверяем существующие маршруты
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Dst != nil &&
			r.Dst.IP.Equal(dst.IP) &&
			bytes.Equal(r.Dst.Mask, dst.Mask) &&
			r.Gw.Equal(gw) {
			return nil // уже есть
		}
	}

	// Добавляем новые
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	}
	return netlink.RouteAdd(route)
}
