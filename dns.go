package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/sr/tsproxy/internal/autocert"

	"github.com/cenkalti/backoff/v4"
	"github.com/dnsimple/dnsimple-go/dnsimple"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"
)

type dnsimpleClient interface {
	ListRecords(context.Context, string, string, *dnsimple.ZoneRecordListOptions) (*dnsimple.ZoneRecordsResponse, error)
	CreateRecord(context.Context, string, string, dnsimple.ZoneRecordAttributes) (*dnsimple.ZoneRecordResponse, error)
	UpdateRecord(context.Context, string, string, int64, dnsimple.ZoneRecordAttributes) (*dnsimple.ZoneRecordResponse, error)
}

type dnsResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func configureDNS(ctx context.Context, cli dnsimpleClient, resolv dnsResolver, accountID string, zone string, ups []upstream, ips []netip.Addr, hostname string) error {
	g, ctx := errgroup.WithContext(ctx)

	// Create A and AAAA records for our Tailscale IPs.
	for _, tsIP := range ips {
		typ := "A"
		if tsIP.Is6() {
			typ = "AAAA"
		}
		tsIP := tsIP
		g.Go(func() error {
			return upsertZoneRecord(ctx, cli, accountID, zone, dnsimple.ZoneRecord{
				Name:    hostname,
				Type:    typ,
				TTL:     dnsTTL,
				Content: tsIP.String(),
			})
		})
	}

	// Create ALIAS records for each upstream.
	for _, u := range ups {
		u := u
		g.Go(func() error {
			return upsertZoneRecord(ctx, cli, accountID, zone, dnsimple.ZoneRecord{
				Name:    u.name,
				Type:    "ALIAS",
				TTL:     dnsTTL,
				Content: hostname + "." + zone,
			})
		})
	}

	// Wait for A and AAAA records to resolve.
	for _, ip := range ips {
		ip := ip
		g.Go(func() error {
			host := fqdn(zone, hostname)
			if err := waitDNSResolveToIP(ctx, resolv, host, ip.String()); err != nil {
				return fmt.Errorf("dns: wait for %s %s: %w", host, ip, err)
			}
			return nil
		})
	}

	return g.Wait()
}

// dnsimpleSolver is a DNS-01 challenge solver for autocert.
func dnsimpleDNS01Solver(logger *slog.Logger, cli dnsimpleClient, aid, zone string) autocert.DNS01ChallengeSolver {
	return func(ctx context.Context, domain string, record string) (func() error, error) {
		name := strings.TrimSuffix(domain, "."+zone)
		txt := "_acme-challenge." + name
		logger.Info("dnsmimple: dns-01 challenge: create TXT record", slog.String("domain", domain), slog.String("TXT", txt))
		err := upsertZoneRecord(ctx, cli, aid, zone, dnsimple.ZoneRecord{
			Type:    "TXT",
			TTL:     300,
			Name:    txt,
			Content: record,
		})
		if err != nil {
			return nil, fmt.Errorf("create TXT record in %s: %w", zone, err)
		}

		logger.Info("dnsmimple: dns-01 challenge: wait for TXT record", slog.String("domain", domain), slog.String("TXT", txt))
		err = backoff.Retry(func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			logger.Info("dnsimple: lookup TXT", slog.String("TXT", txt+"."+zone))
			recs, err := net.DefaultResolver.LookupTXT(ctx, txt+"."+zone)
			if err != nil {
				return err
			}
			for _, r := range recs {
				if r == record {
					return nil
				}
			}
			return fmt.Errorf("TXT %s on %s does not resolve to expected value", name, zone)
		}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))
		if err != nil {
			return nil, fmt.Errorf("dnsimple: dns-01: wait for TXT record: %w", err)
		}
		return func() error { return nil }, nil // TODO(sr) Implement cleanup. }
	}
}

func waitDNSResolveToIP(ctx context.Context, resolver dnsResolver, name string, ip string) error {
	return backoff.Retry(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		ips, err := resolver.LookupIPAddr(ctx, name)
		if err != nil {
			return err
		}
		for _, v := range ips {
			if v.String() == ip {
				return nil
			}
		}
		return fmt.Errorf("%s does not resolve to %s", name, ip)
	}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))
}

// TODO(sr) Write a test.
func upsertZoneRecord(ctx context.Context, cli dnsimpleClient, aid, zone string, rec dnsimple.ZoneRecord) error {
	resp, err := cli.ListRecords(ctx, aid, zone, &dnsimple.ZoneRecordListOptions{
		Name: &rec.Name,
		Type: &rec.Type,
	})
	if err != nil {
		return fmt.Errorf("list records: %w", err)
	}
	if resp != nil && resp.Pagination != nil && resp.Pagination.TotalPages > 1 {
		return errors.New("list records: pagination not implemented")
	}
	if resp == nil || len(resp.Data) == 0 {
		_, err := cli.CreateRecord(ctx, aid, zone, dnsimple.ZoneRecordAttributes{
			Type:    rec.Type,
			Name:    &rec.Name,
			Content: rec.Content,
			TTL:     rec.TTL,
		})
		if err != nil {
			return fmt.Errorf("create record: %w", err)
		}
		return nil
	}
	var found dnsimple.ZoneRecord
	for _, r := range resp.Data {
		if r.Name == rec.Name && r.Type == rec.Type {
			found = r
			break
		}
	}
	// This should not happen?
	if found.ID == 0 {
		return errors.New("matching record not found")
	}
	if _, err := cli.UpdateRecord(ctx, aid, zone, found.ID, dnsimple.ZoneRecordAttributes{
		Name:    &rec.Name,
		TTL:     rec.TTL,
		Content: rec.Content,
	}); err != nil {
		return fmt.Errorf("update record: %w", err)
	}
	return nil
}
