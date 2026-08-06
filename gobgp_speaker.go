package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

type GoBGPSpeakerConfig struct {
	LocalASN     uint32
	RouterID     string
	PeerAddress  string
	PeerASN      uint32
	LocalAddress string
	NextHopV4    string
	NextHopV6    string
	Password     string
	MultihopTTL  uint32
	IPv4         bool
	IPv6         bool
}

type goBGPServer interface {
	Serve()
	StartBgp(context.Context, *api.StartBgpRequest) error
	WatchEvent(context.Context, *api.WatchEventRequest, func(*api.WatchEventResponse)) error
	AddPeer(context.Context, *api.AddPeerRequest) error
	AddPath(context.Context, *api.AddPathRequest) (*api.AddPathResponse, error)
	DeletePath(context.Context, *api.DeletePathRequest) error
	Stop()
}

var (
	_ goBGPServer = (*server.BgpServer)(nil)
	_ BGPSpeaker  = (*GoBGPSpeaker)(nil)
)

var newGoBGPServer = func() goBGPServer { return server.NewBgpServer() }

// GoBGPSpeaker embeds GoBGP in the dns-route process. Its path UUID map mirrors
// the local GoBGP RIB, making Announce idempotent while a peer disconnects and
// reconnects. The map is deliberately process-local and is rebuilt after a
// dns-route restart.
type GoBGPSpeaker struct {
	server goBGPServer
	cfg    GoBGPSpeakerConfig

	watchCancel context.CancelFunc
	established atomic.Bool
	closed      atomic.Bool

	mu    sync.Mutex
	paths map[netip.Prefix][]byte
}

func NewGoBGPSpeaker(ctx context.Context, cfg GoBGPSpeakerConfig) (*GoBGPSpeaker, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	settings := BGPSettings{
		LocalASN:     cfg.LocalASN,
		RouterID:     cfg.RouterID,
		PeerAddress:  cfg.PeerAddress,
		PeerASN:      cfg.PeerASN,
		LocalAddress: cfg.LocalAddress,
		NextHopV4:    cfg.NextHopV4,
		NextHopV6:    cfg.NextHopV6,
		Password:     cfg.Password,
		MultihopTTL:  cfg.MultihopTTL,
	}
	if err := settings.Validate(cfg.IPv4, cfg.IPv6); err != nil {
		return nil, err
	}

	srv := newGoBGPServer()
	if srv == nil {
		return nil, fmt.Errorf("create GoBGP server: nil server")
	}
	go srv.Serve()

	speaker := &GoBGPSpeaker{
		server: srv,
		cfg:    cfg,
		paths:  make(map[netip.Prefix][]byte),
	}
	cleanup := func(err error) (*GoBGPSpeaker, error) {
		srv.Stop()
		return nil, err
	}

	if err := srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:        cfg.LocalASN,
		RouterId:   cfg.RouterID,
		ListenPort: -1,
	}}); err != nil {
		return cleanup(fmt.Errorf("start embedded GoBGP: %w", err))
	}

	watchCtx, cancel := context.WithCancel(context.Background())
	speaker.watchCancel = cancel
	if err := srv.WatchEvent(watchCtx, &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
	}, speaker.handleWatchEvent); err != nil {
		cancel()
		return cleanup(fmt.Errorf("watch GoBGP peer state: %w", err))
	}

	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: cfg.PeerAddress,
			PeerAsn:         cfg.PeerASN,
			AuthPassword:    cfg.Password,
		},
		AfiSafis: goBGPAfiSafis(cfg.IPv4, cfg.IPv6),
	}
	if cfg.LocalAddress != "" {
		peer.Transport = &api.Transport{LocalAddress: cfg.LocalAddress}
	}
	if cfg.MultihopTTL > 1 {
		peer.EbgpMultihop = &api.EbgpMultihop{
			Enabled:     true,
			MultihopTtl: cfg.MultihopTTL,
		}
	}
	if err := srv.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
		cancel()
		return cleanup(fmt.Errorf("add GoBGP peer %s: %w", cfg.PeerAddress, err))
	}
	return speaker, nil
}

func goBGPAfiSafis(ipv4, ipv6 bool) []*api.AfiSafi {
	families := make([]*api.AfiSafi, 0, 2)
	if ipv4 {
		families = append(families, &api.AfiSafi{Config: &api.AfiSafiConfig{
			Family:  goBGPFamily(netip.MustParseAddr("192.0.2.1")),
			Enabled: true,
		}})
	}
	if ipv6 {
		families = append(families, &api.AfiSafi{Config: &api.AfiSafiConfig{
			Family:  goBGPFamily(netip.MustParseAddr("2001:db8::1")),
			Enabled: true,
		}})
	}
	return families
}

func goBGPFamily(addr netip.Addr) *api.Family {
	afi := api.Family_AFI_IP6
	if addr.Unmap().Is4() {
		afi = api.Family_AFI_IP
	}
	return &api.Family{Afi: afi, Safi: api.Family_SAFI_UNICAST}
}

func (s *GoBGPSpeaker) handleWatchEvent(response *api.WatchEventResponse) {
	if s == nil || response == nil || s.closed.Load() {
		return
	}
	event := response.GetPeer()
	if event == nil || event.Type != api.WatchEventResponse_PeerEvent_STATE {
		return
	}
	s.handlePeerState(event.Peer)
}

func (s *GoBGPSpeaker) handlePeerState(peer *api.Peer) {
	if s == nil || peer == nil || s.closed.Load() {
		return
	}
	conf := peer.GetConf()
	if conf != nil && conf.GetNeighborAddress() != "" && conf.GetNeighborAddress() != s.cfg.PeerAddress {
		return
	}
	state := peer.GetState()
	sessionState := api.PeerState_UNKNOWN
	if state != nil {
		sessionState = state.GetSessionState()
	}
	isEstablished := sessionState == api.PeerState_ESTABLISHED
	if previous := s.established.Swap(isEstablished); previous != isEstablished {
		log.Printf("BGP_PEER_STATE peer=%s established=%t state=%v", s.cfg.PeerAddress, isEstablished, sessionState)
	}
}

func (s *GoBGPSpeaker) Established() bool {
	return s != nil && !s.closed.Load() && s.established.Load()
}

func (s *GoBGPSpeaker) Announce(ctx context.Context, route RouteIntent) (bool, error) {
	if s == nil || s.server == nil || s.closed.Load() {
		return false, fmt.Errorf("GoBGP speaker is closed")
	}
	route, err := validateRouteIntent(route)
	if err != nil {
		return false, err
	}
	prefix := route.Prefix.Masked()

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.paths[prefix]; exists {
		return false, nil
	}
	path, err := s.pathForPrefix(prefix)
	if err != nil {
		return false, err
	}
	response, err := s.server.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      path,
	})
	if err != nil {
		return false, err
	}
	if response == nil || len(response.Uuid) == 0 {
		return false, fmt.Errorf("GoBGP returned an empty path UUID for %s", prefix)
	}
	s.paths[prefix] = append([]byte(nil), response.Uuid...)
	return true, nil
}

func (s *GoBGPSpeaker) Withdraw(ctx context.Context, prefix netip.Prefix) (bool, error) {
	if s == nil || s.server == nil || s.closed.Load() {
		return false, fmt.Errorf("GoBGP speaker is closed")
	}
	if !prefix.IsValid() {
		return false, fmt.Errorf("invalid BGP prefix %q", prefix)
	}
	prefix = prefix.Masked()

	s.mu.Lock()
	defer s.mu.Unlock()
	uuid, exists := s.paths[prefix]
	if !exists {
		return false, nil
	}
	if err := s.server.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_GLOBAL,
		Family:    goBGPFamily(prefix.Addr()),
		Uuid:      append([]byte(nil), uuid...),
	}); err != nil {
		return false, err
	}
	delete(s.paths, prefix)
	return true, nil
}

func (s *GoBGPSpeaker) pathForPrefix(prefix netip.Prefix) (*api.Path, error) {
	nlri, err := anypb.New(&api.IPAddressPrefix{
		Prefix:    prefix.Addr().String(),
		PrefixLen: uint32(prefix.Bits()),
	})
	if err != nil {
		return nil, fmt.Errorf("encode BGP NLRI %s: %w", prefix, err)
	}
	origin, err := anypb.New(&api.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, fmt.Errorf("encode BGP origin for %s: %w", prefix, err)
	}
	family := goBGPFamily(prefix.Addr())
	attributes := []*anypb.Any{origin}
	if prefix.Addr().Is4() {
		nextHop, err := anypb.New(&api.NextHopAttribute{NextHop: s.cfg.NextHopV4})
		if err != nil {
			return nil, fmt.Errorf("encode IPv4 next hop for %s: %w", prefix, err)
		}
		attributes = append(attributes, nextHop)
	} else {
		mpReach, err := anypb.New(&api.MpReachNLRIAttribute{
			Family:   family,
			NextHops: []string{s.cfg.NextHopV6},
			Nlris:    []*anypb.Any{nlri},
		})
		if err != nil {
			return nil, fmt.Errorf("encode IPv6 next hop for %s: %w", prefix, err)
		}
		attributes = append(attributes, mpReach)
	}
	return &api.Path{
		Family: family,
		Nlri:   nlri,
		Pattrs: attributes,
	}, nil
}

func (s *GoBGPSpeaker) Close() error {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.watchCancel != nil {
		s.watchCancel()
	}
	s.established.Store(false)
	if s.server != nil {
		s.server.Stop()
	}
	s.mu.Lock()
	clear(s.paths)
	s.mu.Unlock()
	return nil
}
