package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type fakeLocalClient struct {
	whois func(context.Context, string) (*apitype.WhoIsResponse, error)
}

func (c *fakeLocalClient) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return c.whois(ctx, remoteAddr)
}

func TestReverseProxy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		whois       func(context.Context, string) (*apitype.WhoIsResponse, error)
		want        int
		wantHeaders map[string]string
	}{
		{
			name: "tailscale whois error",
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return nil, errors.New("whois error")
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "tailscale whois no profile",
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{}, nil
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "tailscale whois no node",
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login"}}, nil
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "tailscale whois ok (tagged node)",
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"foo"}}}, nil
			},
			want: http.StatusOK,
		},
		{
			name: "tailscale whois ok (user)",
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login", DisplayName: "name"}, Node: &tailcfg.Node{Name: "login.ts.net"}}, nil
			},
			want: http.StatusOK,
			wantHeaders: map[string]string{
				"X-Webauth-User": "login",
				"X-Webauth-Name": "name",
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lc := &fakeLocalClient{whois: tc.whois}
			be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range r.Header {
					w.Header().Set(k, v[0])
				}
				fmt.Fprintln(w, "Hi from the backend.")
			}))
			defer be.Close()
			beURL, err := url.Parse(be.URL)
			if err != nil {
				log.Fatal(err)
			}
			px := httptest.NewServer(newReverseProxy(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{})), lc, beURL, false))
			defer px.Close()

			resp, err := http.Get(px.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if want, got := tc.want, resp.StatusCode; want != got {
				t.Errorf("want status %d, got: %d", want, got)
			}
			if tc.wantHeaders == nil {
				tc.wantHeaders = map[string]string{
					"X-Webauth-User": "",
					"X-Webauth-Name": "",
				}
			}
			for k, want := range tc.wantHeaders {
				if got := resp.Header.Get(k); got != want {
					t.Errorf("want header %s %s, got: %s", k, want, got)
				}
			}
		})
	}
}

func TestServeDiscovery(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(serveDiscovery("self", []target{
		{magicDNS: "b", prometheus: true},
		{magicDNS: "x"},
		{},
		{magicDNS: "a", prometheus: true},
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if want, got := http.StatusOK, resp.StatusCode; want != got {
		t.Errorf("want status %d, got: %d", want, got)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(`[{"targets":["a","b","self"]}]`, string(b)); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()

	c, err := testutil.GatherAndCount(prometheus.DefaultGatherer)
	if err != nil {
		t.Fatalf("GatherAndCount: %v", err)
	}
	if c == 0 {
		t.Fatalf("no metrics collected")
	}

	lint, err := testutil.GatherAndLint(prometheus.DefaultGatherer)
	if err != nil {
		t.Fatalf("CollectAndLint: %v", err)
	}
	if len(lint) > 0 {
		t.Error("lint problems detected")
	}
	for _, prob := range lint {
		t.Errorf("lint: %s: %s", prob.Metric, prob.Text)
	}
}
