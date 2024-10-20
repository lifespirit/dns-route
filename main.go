package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
)

//TIP To run your code, right-click the code and select <b>Run</b>. Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.

var re *regexp.Regexp

var routeAddress = net.ParseIP(os.Getenv("ROUTE"))
var dnsAddress = os.Getenv("DNSADDRESS")

func searchRoute(routesTable []netlink.Route) int {
	var route = -1
	for index, oneRoute := range routesTable {
		if oneRoute.Gw.Equal(routeAddress) {
			route = index
		}
	}
	return route
}

func resolve(domain string, qtype uint16) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := new(dns.Client)
	in, _, err := c.Exchange(m, dnsAddress)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	matches := re.FindStringSubmatch(domain)
	if qtype == dns.TypeA && len(matches) > 0 {
		fmt.Printf("Listed domain found: %s\n", domain)
		for _, ans := range in.Answer {
			address := net.ParseIP(strings.ReplaceAll(ans.String(), ans.Header().String(), ""))
			if address != nil {
				routes, err := netlink.RouteGet(address)
				if err != nil {
					log.Printf("Can't get route for %s from netlink: %v", address, err)
				}
				searchResult := searchRoute(routes)
				if searchResult < 0 {
					log.Printf("Can't find route to GW %s for %s", routeAddress, domain)
					destination := &net.IPNet{
						IP: address, Mask: net.CIDRMask(32, 32),
					}
					customRoute := &netlink.Route{
						Dst: destination,
						Gw:  routeAddress,
					}
					err = netlink.RouteAdd(customRoute)
					if err != nil {
						log.Printf("Can't add custom route for %s to netlink: %v", customRoute, err)
					}
					log.Printf("Added route: %s via %s", address, routeAddress)
				}
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
		fmt.Printf("DNS request: %s\n", question.Name)
		answers := resolve(question.Name, question.Qtype)
		msg.Answer = append(msg.Answer, answers...)
	}

	err := w.WriteMsg(msg)
	if err != nil {
		fmt.Println(err)
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

	go func() {
		tcpHandler := new(dnsHandler)
		tcpServer := &dns.Server{
			Addr:      address,
			Net:       "tcp",
			Handler:   tcpHandler,
			ReusePort: true,
		}

		fmt.Printf("Starting tcp DNS server on %s\n", address)
		err := tcpServer.ListenAndServe()
		if err != nil {
			fmt.Printf("Failed to start tcp server: %s\n", err.Error())
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
	fmt.Printf("Starting udp DNS server on %s\n", address)
	err := udpServer.ListenAndServe()
	if err != nil {
		fmt.Printf("Failed to start udp server: %s\n", err.Error())
	}

}

//TIP See GoLand help at <a href="https://www.jetbrains.com/help/go/">jetbrains.com/help/go/</a>.
// Also, you can try interactive lessons for GoLand by selecting 'Help | Learn IDE Features' from the main menu.
