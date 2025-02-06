package main

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

//TIP To run your code, right-click the code and select <b>Run</b>. Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.

var re *regexp.Regexp
var whoisRe *regexp.Regexp

var routeAddress = net.ParseIP(os.Getenv("ROUTE"))
var dnsAddress = os.Getenv("DNSADDRESS")
var whoisAddress = os.Getenv("WHOISADDRESS")

func whois(ipaddr string) (net.IP, int, error) {

	address := net.ParseIP(whoisAddress)
	if address == nil {
		log.Printf("whois address not an IP address: %s", whoisAddress)
		answer := resolve(whoisAddress, dns.TypeA, true)
		address = net.ParseIP(strings.ReplaceAll(answer[0].String(), answer[0].Header().String(), ""))
		log.Printf("whois address resolved: %v", address)
	}
	if address != nil {
		conn, err := net.Dial("tcp", address.String()+":43")
		if err != nil {
			log.Printf("Can't connect to whois server. Error: %s", err)
			return nil, 0, err
		}
		defer conn.Close()

		_, err = conn.Write([]byte("-K -l " + ipaddr + "\r\n"))
		if err != nil {
			log.Printf("Can't send ip addr to whois server. Error: %s", err)
			return nil, 0, err
		}

		buf := make([]byte, 1024)

		result := []byte{}

		for {
			numBytes, err := conn.Read(buf)
			sbuf := buf[0:numBytes]
			result = append(result, sbuf...)
			if err != nil {
				break
			}
		}

		matches := whoisRe.FindStringSubmatch(string(result))
		if len(matches) >= 3 {
			ipNetwork := net.ParseIP(matches[1])
			if ipNetwork == nil {
				log.Printf("Can't convert ip addr to IP.")
				return nil, 0, errors.New("can't convert ip addr to IP")
			}
			ipMask, err := strconv.Atoi(matches[2])
			if err != nil {
				log.Printf("Can't convert ip mask to int. Error: %s", err)
				return ipNetwork, 0, errors.New("can't convert ip mask string to int")
			}
			return net.ParseIP(matches[1]), ipMask, nil
		}
	}
	return nil, 0, errors.New("can't parse whois IP address")
}

func searchGW(routesTable []netlink.Route) int {
	var route = -1
	for index, oneRoute := range routesTable {
		if oneRoute.Gw.Equal(routeAddress) {
			route = index
		}
	}
	return route
}

func setRoute(address net.IP, skipWhois bool) {
	routes, err := netlink.RouteGet(address)
	if err != nil {
		log.Printf("Can't get route for %s from netlink: %v", address, err)
	}
	searchResult := searchGW(routes)
	if searchResult < 0 {
		log.Printf("Can't find route %s to GW %s", address, routeAddress)
		mask := 32
		if whoisAddress != "" && !skipWhois {
			log.Printf("Try send request to whois server.")
			ipNetwork, ipMask, err := whois(address.String())
			if err != nil {
				log.Printf("Can't get ip network for %s from whois server: %v", address, err)
			} else {
				log.Printf("Done. Network: %s, Mask: %v", ipNetwork, ipMask)
				address = ipNetwork
				mask = ipMask
			}
		}
		destination := &net.IPNet{
			IP: address, Mask: net.CIDRMask(mask, 32),
		}
		customRoute := &netlink.Route{
			Dst: destination,
			Gw:  routeAddress,
		}
		err = netlink.RouteAdd(customRoute)
		if err != nil {
			log.Printf("Can't add custom route for %s to netlink: %v", customRoute, err)
		}
		log.Printf("Added route: %s/%v via %s", address, mask, routeAddress)
	}
}

func resolve(domain string, qtype uint16, skipWhois bool) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := new(dns.Client)
	in, _, err := c.Exchange(m, dnsAddress)
	if err != nil {
		log.Println(err)
		return nil
	}

	matches := re.FindStringSubmatch(domain)
	if qtype == dns.TypeA && len(matches) > 0 {
		log.Printf("Listed domain found: %s\n", domain)
		for _, ans := range in.Answer {
			address := net.ParseIP(strings.ReplaceAll(ans.String(), ans.Header().String(), ""))
			if address != nil {
				setRoute(address, skipWhois)
			}
		}
	}
	return in.Answer
}

type dnsHandler struct{}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		log.Printf("DNS request: %s\n", question.Name)
		answers := resolve(question.Name, question.Qtype, false)
		msg.Answer = append(msg.Answer, answers...)
	}

	err := w.WriteMsg(msg)
	if err != nil {
		log.Println(err)
	}
}

func main() {

	domains := strings.Split(os.Getenv("DOMAINS"), ",")
	address := os.Getenv("ADDRESS")
	var filter string
	for index, domain := range domains {
		if index > 0 {
			filter += "|"
		}
		filter += domain + ".$"
	}
	re = regexp.MustCompile(filter)
	whoisRe = regexp.MustCompile(`route: (\S+)/(\d+)`)

	go func() {
		tcpHandler := new(dnsHandler)
		tcpServer := &dns.Server{
			Addr:      address,
			Net:       "tcp",
			Handler:   tcpHandler,
			ReusePort: true,
		}

		log.Printf("Starting tcp DNS server on %s\n", address)
		err := tcpServer.ListenAndServe()
		if err != nil {
			log.Printf("Failed to start tcp server: %s\n", err.Error())
		}
	}()

	udpHandler := new(dnsHandler)
	udpServer := &dns.Server{
		Addr:      address,
		Net:       "udp",
		Handler:   udpHandler,
		UDPSize:   65535,
		ReusePort: true,
	}
	log.Printf("Starting udp DNS server on %s\n", address)
	err := udpServer.ListenAndServe()
	if err != nil {
		log.Printf("Failed to start udp server: %s\n", err.Error())
	}

}

//TIP See GoLand help at <a href="https://www.jetbrains.com/help/go/">jetbrains.com/help/go/</a>.
// Also, you can try interactive lessons for GoLand by selecting 'Help | Learn IDE Features' from the main menu.
