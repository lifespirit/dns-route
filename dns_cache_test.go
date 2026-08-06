package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type captureDNSResponseWriter struct {
	msg *dns.Msg
}

func (w *captureDNSResponseWriter) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (w *captureDNSResponseWriter) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (w *captureDNSResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg.Copy()
	return nil
}
func (w *captureDNSResponseWriter) Write(payload []byte) (int, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return 0, err
	}
	w.msg = msg
	return len(payload), nil
}
func (w *captureDNSResponseWriter) Close() error        { return nil }
func (w *captureDNSResponseWriter) TsigStatus() error   { return nil }
func (w *captureDNSResponseWriter) TsigTimersOnly(bool) {}
func (w *captureDNSResponseWriter) Hijack()             {}

func TestCachedDNSResponseAgesTTLWithoutChangingOPTMetadata(t *testing.T) {
	storedAt := time.Unix(1_700_000_000, 0)
	msg := new(dns.Msg)
	msg.Id = 10
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.0.2.10")},
	}
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 90}, Ns: "ns.example.test."},
	}
	msg.SetEdns0(1232, true)
	optTTL := msg.IsEdns0().Hdr.Ttl

	got := cachedDNSResponse(cacheEntry{msg: msg, storedAt: storedAt}, 55, storedAt.Add(30*time.Second))
	if got == nil {
		t.Fatal("cached response is nil")
	}
	if got.Id != 55 {
		t.Fatalf("response id=%d, want 55", got.Id)
	}
	if got.Answer[0].Header().Ttl != 90 {
		t.Fatalf("answer TTL=%d, want 90", got.Answer[0].Header().Ttl)
	}
	if got.Ns[0].Header().Ttl != 60 {
		t.Fatalf("authority TTL=%d, want 60", got.Ns[0].Header().Ttl)
	}
	if got.IsEdns0().Hdr.Ttl != optTTL {
		t.Fatalf("OPT metadata TTL=%d, want unchanged %d", got.IsEdns0().Hdr.Ttl, optTTL)
	}
	if msg.Answer[0].Header().Ttl != 120 {
		t.Fatalf("cached source message mutated: TTL=%d", msg.Answer[0].Header().Ttl)
	}
}

func TestDNSCacheKeyIncludesCompleteQuestionAndDNSFlags(t *testing.T) {
	policy := forwardPolicy{CacheKey: "default"}
	base := new(dns.Msg)
	base.SetQuestion("Example.TEST.", dns.TypeA)
	base.RecursionDesired = true

	baseKey, err := dnsCacheKey(policy, base)
	if err != nil {
		t.Fatalf("base key: %v", err)
	}

	equivalent := base.Copy()
	equivalent.Id = 65000
	equivalent.Compress = true
	equivalent.Question[0].Name = "example.test"
	equivalentKey, err := dnsCacheKey(policy, equivalent)
	if err != nil {
		t.Fatalf("equivalent key: %v", err)
	}
	if equivalentKey != baseKey {
		t.Fatalf("equivalent names produced different keys: %q != %q", equivalentKey, baseKey)
	}

	variants := []*dns.Msg{}
	qclass := base.Copy()
	qclass.Question[0].Qclass = dns.ClassCHAOS
	variants = append(variants, qclass)

	qtype := base.Copy()
	qtype.Question[0].Qtype = 65400
	variants = append(variants, qtype)

	checkingDisabled := base.Copy()
	checkingDisabled.CheckingDisabled = true
	variants = append(variants, checkingDisabled)

	dnssec := base.Copy()
	dnssec.SetEdns0(1232, true)
	variants = append(variants, dnssec)

	for i, variant := range variants {
		key, err := dnsCacheKey(policy, variant)
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		if key == baseKey {
			t.Fatalf("variant %d did not change cache key", i)
		}
	}
}

func TestHandleDNSRejectsMultipleQuestions(t *testing.T) {
	req := new(dns.Msg)
	req.Id = 1234
	req.Question = []dns.Question{
		{Name: "one.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "two.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}
	writer := &captureDNSResponseWriter{}
	app := &App{}

	app.handleDNS(writer, req)

	if writer.msg == nil {
		t.Fatal("no DNS response written")
	}
	if writer.msg.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode=%d, want FORMERR", writer.msg.Rcode)
	}
	if writer.msg.Id != req.Id {
		t.Fatalf("response id=%d, want %d", writer.msg.Id, req.Id)
	}
	if app.servfailCount != 0 {
		t.Fatalf("FORMERR counted as SERVFAIL: %d", app.servfailCount)
	}
}

func TestDNSCacheKeyRejectsMultipleQuestions(t *testing.T) {
	req := &dns.Msg{Question: []dns.Question{{Name: "one.", Qtype: dns.TypeA}, {Name: "two.", Qtype: dns.TypeA}}}
	if _, err := dnsCacheKey(forwardPolicy{CacheKey: "default"}, req); err == nil {
		t.Fatal("multiple questions unexpectedly accepted")
	}
}

func TestMinimumCacheTTLIncludesAuthorityAndAdditionalSections(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.20")},
	}
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 90}, Ns: "ns.example.test."},
	}
	msg.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.53")},
	}
	msg.SetEdns0(1232, true)

	got, ok := minimumCacheTTL(msg)
	if !ok {
		t.Fatal("cacheable response was rejected")
	}
	if got != 30 {
		t.Fatalf("minimum TTL=%d, want 30", got)
	}
}

func TestMinimumCacheTTLRequiresPositiveAnswerSet(t *testing.T) {
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}},
	}
	if _, ok := minimumCacheTTL(msg); ok {
		t.Fatal("negative response unexpectedly enabled in positive-answer cache")
	}
}
