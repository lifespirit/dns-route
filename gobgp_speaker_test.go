package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
)

type fakeGoBGPServer struct {
	mu sync.Mutex

	serveStarted chan struct{}
	serveOnce    sync.Once
	startReq     *api.StartBgpRequest
	watchReq     *api.WatchEventRequest
	watchFn      func(*api.WatchEventResponse)
	peerReq      *api.AddPeerRequest
	paths        []*api.AddPathRequest
	deletes      []*api.DeletePathRequest
	stopCount    int

	startErr  error
	watchErr  error
	peerErr   error
	pathErr   error
	deleteErr error
	uuid      []byte
}

func newFakeGoBGPServer() *fakeGoBGPServer {
	return &fakeGoBGPServer{serveStarted: make(chan struct{}), uuid: []byte{1, 2, 3}}
}

func (s *fakeGoBGPServer) Serve() {
	s.serveOnce.Do(func() { close(s.serveStarted) })
}
func (s *fakeGoBGPServer) StartBgp(_ context.Context, req *api.StartBgpRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startReq = req
	return s.startErr
}
func (s *fakeGoBGPServer) WatchEvent(_ context.Context, req *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchReq = req
	s.watchFn = fn
	return s.watchErr
}
func (s *fakeGoBGPServer) AddPeer(_ context.Context, req *api.AddPeerRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerReq = req
	return s.peerErr
}
func (s *fakeGoBGPServer) AddPath(_ context.Context, req *api.AddPathRequest) (*api.AddPathResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append(s.paths, req)
	if s.pathErr != nil {
		return nil, s.pathErr
	}
	return &api.AddPathResponse{Uuid: append([]byte(nil), s.uuid...)}, nil
}
func (s *fakeGoBGPServer) DeletePath(_ context.Context, req *api.DeletePathRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes = append(s.deletes, req)
	return s.deleteErr
}
func (s *fakeGoBGPServer) Stop() {
	s.mu.Lock()
	s.stopCount++
	s.mu.Unlock()
}

func validGoBGPSpeakerConfig() GoBGPSpeakerConfig {
	return GoBGPSpeakerConfig{
		LocalASN:     65001,
		RouterID:     "192.0.2.1",
		PeerAddress:  "192.0.2.2",
		PeerASN:      65002,
		LocalAddress: "192.0.2.1",
		NextHopV4:    "192.0.2.1",
		NextHopV6:    "2001:db8::1",
		MultihopTTL:  1,
		IPv4:         true,
		IPv6:         true,
	}
}

func installFakeGoBGPServer(t *testing.T, fake *fakeGoBGPServer) {
	t.Helper()
	original := newGoBGPServer
	newGoBGPServer = func() goBGPServer { return fake }
	t.Cleanup(func() { newGoBGPServer = original })
}

func TestNewGoBGPSpeakerConfiguresServerAndPeer(t *testing.T) {
	fake := newFakeGoBGPServer()
	installFakeGoBGPServer(t, fake)
	cfg := validGoBGPSpeakerConfig()
	cfg.Password = "secret"
	cfg.MultihopTTL = 5

	speaker, err := NewGoBGPSpeaker(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new speaker: %v", err)
	}
	t.Cleanup(func() { _ = speaker.Close() })

	select {
	case <-fake.serveStarted:
	case <-time.After(time.Second):
		t.Fatal("GoBGP Serve was not started")
	}
	if fake.startReq == nil || fake.startReq.Global == nil {
		t.Fatal("StartBgp was not called")
	}
	if fake.startReq.Global.Asn != cfg.LocalASN || fake.startReq.Global.RouterId != cfg.RouterID || fake.startReq.Global.ListenPort != -1 {
		t.Fatalf("global config=%+v", fake.startReq.Global)
	}
	if fake.watchReq == nil || fake.watchReq.Peer == nil || fake.watchFn == nil {
		t.Fatal("peer watcher was not registered")
	}
	if fake.peerReq == nil || fake.peerReq.Peer == nil {
		t.Fatal("AddPeer was not called")
	}
	peer := fake.peerReq.Peer
	if peer.Conf.NeighborAddress != cfg.PeerAddress || peer.Conf.PeerAsn != cfg.PeerASN || peer.Conf.AuthPassword != cfg.Password {
		t.Fatalf("peer conf=%+v", peer.Conf)
	}
	if peer.Transport == nil || peer.Transport.LocalAddress != cfg.LocalAddress {
		t.Fatalf("peer transport=%+v", peer.Transport)
	}
	if peer.EbgpMultihop == nil || !peer.EbgpMultihop.Enabled || peer.EbgpMultihop.MultihopTtl != 5 {
		t.Fatalf("multihop=%+v", peer.EbgpMultihop)
	}
	if len(peer.AfiSafis) != 2 {
		t.Fatalf("AFI/SAFI count=%d, want 2", len(peer.AfiSafis))
	}
}

func TestGoBGPSpeakerTracksPeerState(t *testing.T) {
	fake := newFakeGoBGPServer()
	installFakeGoBGPServer(t, fake)
	speaker, err := NewGoBGPSpeaker(context.Background(), validGoBGPSpeakerConfig())
	if err != nil {
		t.Fatalf("new speaker: %v", err)
	}
	defer speaker.Close()

	speaker.handlePeerState(&api.Peer{
		Conf:  &api.PeerConf{NeighborAddress: "192.0.2.2"},
		State: &api.PeerState{SessionState: api.PeerState_ESTABLISHED},
	})
	if !speaker.Established() {
		t.Fatal("established state was not recorded")
	}
	speaker.handlePeerState(&api.Peer{
		Conf:  &api.PeerConf{NeighborAddress: "198.51.100.2"},
		State: &api.PeerState{SessionState: api.PeerState_IDLE},
	})
	if !speaker.Established() {
		t.Fatal("state from another peer changed the configured peer")
	}
	speaker.handlePeerState(&api.Peer{
		Conf:  &api.PeerConf{NeighborAddress: "192.0.2.2"},
		State: &api.PeerState{SessionState: api.PeerState_ACTIVE},
	})
	if speaker.Established() {
		t.Fatal("non-established state was not recorded")
	}
}

func TestGoBGPSpeakerAnnounceAndWithdrawIPv4(t *testing.T) {
	fake := newFakeGoBGPServer()
	installFakeGoBGPServer(t, fake)
	speaker, err := NewGoBGPSpeaker(context.Background(), validGoBGPSpeakerConfig())
	if err != nil {
		t.Fatalf("new speaker: %v", err)
	}
	defer speaker.Close()

	route := RouteIntent{
		IP:         netip.MustParseAddr("198.51.100.8"),
		Prefix:     netip.MustParsePrefix("198.51.100.0/24"),
		ResolvedBy: PrefixSourceCymru,
	}
	changed, err := speaker.Announce(context.Background(), route)
	if err != nil || !changed {
		t.Fatalf("announce changed=%t error=%v", changed, err)
	}
	changed, err = speaker.Announce(context.Background(), route)
	if err != nil || changed {
		t.Fatalf("duplicate announce changed=%t error=%v", changed, err)
	}
	if len(fake.paths) != 1 {
		t.Fatalf("AddPath calls=%d, want 1", len(fake.paths))
	}
	path := fake.paths[0].Path
	if path == nil || path.Family.Afi != api.Family_AFI_IP || path.Family.Safi != api.Family_SAFI_UNICAST {
		t.Fatalf("path family=%+v", path)
	}
	var nlri api.IPAddressPrefix
	if err := path.Nlri.UnmarshalTo(&nlri); err != nil {
		t.Fatalf("decode NLRI: %v", err)
	}
	if nlri.Prefix != "198.51.100.0" || nlri.PrefixLen != 24 {
		t.Fatalf("NLRI=%+v", nlri)
	}
	foundNextHop := false
	for _, attr := range path.Pattrs {
		var nextHop api.NextHopAttribute
		if err := attr.UnmarshalTo(&nextHop); err == nil {
			foundNextHop = nextHop.NextHop == "192.0.2.1"
		}
	}
	if !foundNextHop {
		t.Fatal("IPv4 NEXT_HOP attribute not found")
	}

	changed, err = speaker.Withdraw(context.Background(), route.Prefix)
	if err != nil || !changed {
		t.Fatalf("withdraw changed=%t error=%v", changed, err)
	}
	if len(fake.deletes) != 1 || string(fake.deletes[0].Uuid) != string(fake.uuid) {
		t.Fatalf("DeletePath requests=%+v", fake.deletes)
	}
	changed, err = speaker.Withdraw(context.Background(), route.Prefix)
	if err != nil || changed {
		t.Fatalf("duplicate withdraw changed=%t error=%v", changed, err)
	}
}

func TestGoBGPSpeakerBuildsIPv6MPReach(t *testing.T) {
	fake := newFakeGoBGPServer()
	installFakeGoBGPServer(t, fake)
	speaker, err := NewGoBGPSpeaker(context.Background(), validGoBGPSpeakerConfig())
	if err != nil {
		t.Fatalf("new speaker: %v", err)
	}
	defer speaker.Close()

	route := RouteIntent{
		IP:         netip.MustParseAddr("2001:db8:1::10"),
		Prefix:     netip.MustParsePrefix("2001:db8:1::/48"),
		ResolvedBy: PrefixSourceCymru,
	}
	if _, err := speaker.Announce(context.Background(), route); err != nil {
		t.Fatalf("announce: %v", err)
	}
	path := fake.paths[0].Path
	if path.Family.Afi != api.Family_AFI_IP6 {
		t.Fatalf("AFI=%v, want IPv6", path.Family.Afi)
	}
	found := false
	for _, attr := range path.Pattrs {
		var mp api.MpReachNLRIAttribute
		if err := attr.UnmarshalTo(&mp); err == nil {
			found = len(mp.NextHops) == 1 && mp.NextHops[0] == "2001:db8::1" && len(mp.Nlris) == 1
		}
	}
	if !found {
		t.Fatal("IPv6 MP_REACH_NLRI attribute not found")
	}
}

func TestNewGoBGPSpeakerCleansUpStartupErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*fakeGoBGPServer)
		want string
	}{
		{"start", func(s *fakeGoBGPServer) { s.startErr = errors.New("start failed") }, "start embedded GoBGP"},
		{"watch", func(s *fakeGoBGPServer) { s.watchErr = errors.New("watch failed") }, "watch GoBGP peer state"},
		{"peer", func(s *fakeGoBGPServer) { s.peerErr = errors.New("peer failed") }, "add GoBGP peer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeGoBGPServer()
			tc.set(fake)
			original := newGoBGPServer
			newGoBGPServer = func() goBGPServer { return fake }
			defer func() { newGoBGPServer = original }()

			if _, err := NewGoBGPSpeaker(context.Background(), validGoBGPSpeakerConfig()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want substring %q", err, tc.want)
			}
			if fake.stopCount != 1 {
				t.Fatalf("Stop calls=%d, want 1", fake.stopCount)
			}
		})
	}
}

func TestGoBGPSpeakerRejectsEmptyPathUUID(t *testing.T) {
	fake := newFakeGoBGPServer()
	fake.uuid = nil
	installFakeGoBGPServer(t, fake)
	speaker, err := NewGoBGPSpeaker(context.Background(), validGoBGPSpeakerConfig())
	if err != nil {
		t.Fatalf("new speaker: %v", err)
	}
	defer speaker.Close()

	_, err = speaker.Announce(context.Background(), RouteIntent{
		IP:     netip.MustParseAddr("192.0.2.8"),
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	})
	if err == nil || !strings.Contains(err.Error(), "empty path UUID") {
		t.Fatalf("error=%v", err)
	}
}
