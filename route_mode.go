package main

import (
	"fmt"
	"net/netip"
	"strings"
)

type RouteMode string

const (
	RouteModeKernel    RouteMode = "kernel"
	RouteModeBGP       RouteMode = "bgp"
	RouteModeKernelBGP RouteMode = "kernel+bgp"
)

func parseRouteMode(v string) (RouteMode, error) {
	mode := RouteMode(strings.ToLower(strings.TrimSpace(v)))
	if mode == "" {
		return RouteModeKernel, nil
	}
	switch mode {
	case RouteModeKernel, RouteModeBGP, RouteModeKernelBGP:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported route_mode=%q", v)
	}
}

func (m RouteMode) UsesKernel() bool {
	return m == RouteModeKernel || m == RouteModeKernelBGP
}

func (m RouteMode) UsesBGP() bool {
	return m == RouteModeBGP || m == RouteModeKernelBGP
}

type BGPSettings struct {
	LocalASN           uint32
	RouterID           string
	PeerAddress        string
	PeerASN            uint32
	LocalAddress       string
	NextHopV4          string
	NextHopV6          string
	Password           string
	MultihopTTL        uint32
	RequireEstablished bool
}

func (s BGPSettings) Validate(ipv4, ipv6 bool) error {
	if !ipv4 && !ipv6 {
		return fmt.Errorf("BGP mode requires route_ipv4 or route_ipv6")
	}
	if s.LocalASN == 0 {
		return fmt.Errorf("bgp_local_asn must be greater than zero")
	}
	if s.PeerASN == 0 {
		return fmt.Errorf("bgp_peer_asn must be greater than zero")
	}

	routerID, err := netip.ParseAddr(strings.TrimSpace(s.RouterID))
	if err != nil || !routerID.Is4() || routerID.IsUnspecified() {
		return fmt.Errorf("bgp_router_id must be a non-unspecified IPv4 address")
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(s.PeerAddress))
	if err != nil || peer.IsUnspecified() {
		return fmt.Errorf("bgp_peer_address must be a non-unspecified IP address")
	}
	if local := strings.TrimSpace(s.LocalAddress); local != "" {
		addr, err := netip.ParseAddr(local)
		if err != nil || addr.IsUnspecified() {
			return fmt.Errorf("bgp_local_address must be a non-unspecified IP address")
		}
		if addr.Is4() != peer.Is4() {
			return fmt.Errorf("bgp_local_address and bgp_peer_address must use the same address family")
		}
	}
	if s.MultihopTTL == 0 || s.MultihopTTL > 255 {
		return fmt.Errorf("bgp_multihop_ttl must be between 1 and 255")
	}
	if ipv4 {
		addr, err := netip.ParseAddr(strings.TrimSpace(s.NextHopV4))
		if err != nil || !addr.Is4() || addr.IsUnspecified() {
			return fmt.Errorf("bgp_next_hop_v4 must be a non-unspecified IPv4 address")
		}
	}
	if ipv6 {
		addr, err := netip.ParseAddr(strings.TrimSpace(s.NextHopV6))
		if err != nil || !addr.Is6() || addr.Is4In6() || addr.IsUnspecified() {
			return fmt.Errorf("bgp_next_hop_v6 must be a non-unspecified IPv6 address")
		}
	}
	return nil
}

func (s BGPSettings) SpeakerConfig(ipv4, ipv6 bool) (GoBGPSpeakerConfig, error) {
	if err := s.Validate(ipv4, ipv6); err != nil {
		return GoBGPSpeakerConfig{}, err
	}
	return GoBGPSpeakerConfig{
		LocalASN:     s.LocalASN,
		RouterID:     strings.TrimSpace(s.RouterID),
		PeerAddress:  strings.TrimSpace(s.PeerAddress),
		PeerASN:      s.PeerASN,
		LocalAddress: strings.TrimSpace(s.LocalAddress),
		NextHopV4:    strings.TrimSpace(s.NextHopV4),
		NextHopV6:    strings.TrimSpace(s.NextHopV6),
		Password:     s.Password,
		MultihopTTL:  s.MultihopTTL,
		IPv4:         ipv4,
		IPv6:         ipv6,
	}, nil
}
