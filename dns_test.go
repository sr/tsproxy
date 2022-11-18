package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type fakeDNSimpleClient struct {
	dnsimpleClient
	records []dnsimple.ZoneRecord
	mu      sync.Mutex
}

func (c *fakeDNSimpleClient) ListRecords(context.Context, string, string, *dnsimple.ZoneRecordListOptions) (*dnsimple.ZoneRecordsResponse, error) {
	return nil, nil
}

func (c *fakeDNSimpleClient) CreateRecord(ctx context.Context, aid string, zone string, rec dnsimple.ZoneRecordAttributes) (*dnsimple.ZoneRecordResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, dnsimple.ZoneRecord{
		Name:    *rec.Name,
		Type:    rec.Type,
		Content: rec.Content,
		TTL:     rec.TTL,
	})
	return nil, nil
}

type fakeDNSResolver struct {
	ips []net.IPAddr
}

func (r *fakeDNSResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.ips, nil
}

func TestConfigureDNS(t *testing.T) {
	t.Parallel()

	dns := &fakeDNSimpleClient{}
	resolv := &fakeDNSResolver{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}}}
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}
	ups := []upstream{{name: "test1"}, {name: "test2"}}
	err := configureDNS(context.TODO(), dns, resolv, "1234", "example.com", ups, ips, "self")
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsimple.ZoneRecord{
		{Type: "A", Name: "self", Content: "127.0.0.1"},
		{Type: "AAAA", Name: "self", Content: "::1"},
		{Type: "ALIAS", Name: "test2", Content: "self.example.com"},
		{Type: "ALIAS", Name: "test1", Content: "self.example.com"},
	}
	less := func(a, b dnsimple.ZoneRecord) bool {
		return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
	}
	if diff := cmp.Diff(want, dns.records, cmpopts.SortSlices(less), cmpopts.IgnoreFields(dnsimple.ZoneRecord{}, "TTL")); diff != "" {
		t.Errorf("dns records mismatch (-want +got):\n%s", diff)
	}
}
