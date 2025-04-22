package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if c.whois == nil {
		return nil, errors.New("not implemented")
	}
	return c.whois(ctx, remoteAddr)
}

func TestTSHandlers(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))

	for _, tc := range []struct {
		name        string
		whois       func(context.Context, string) (*apitype.WhoIsResponse, error)
		handler     func(*slog.Logger, tailscaleLocalClient, http.Handler) http.Handler
		wantNext    bool
		wantStatus  int
		wantHeaders map[string]string
		wantBody    string
	}{
		{
			name:    "tailnet: tailscale whois error",
			handler: tailnet,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return nil, errors.New("whois error")
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "tailnet: tailscale whois no profile",
			handler: tailnet,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{Node: &tailcfg.Node{Tags: []string{"foo"}}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "tailnet: tailscale whois no node",
			handler: tailnet,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login"}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "tailnet: tailscale whois ok (tagged node)",
			handler: tailnet,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"foo"}}}, nil
			},
			wantNext:   true,
			wantStatus: http.StatusOK,
			wantBody:   "OK",
			wantHeaders: map[string]string{
				"X-Webauth-User": "",
				"X-Webauth-Name": "",
			},
		},
		{
			name:    "tailnet: tailscale whois ok (user)",
			handler: tailnet,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login", DisplayName: "name"}, Node: &tailcfg.Node{Name: "login.ts.net"}}, nil
			},
			wantNext:   true,
			wantStatus: http.StatusOK,
			wantBody:   "OK",
			wantHeaders: map[string]string{
				"X-Webauth-User": "login",
				"X-Webauth-Name": "name",
			},
		},
		{
			name:    "insecure: tailscale whois error",
			handler: insecureFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return nil, errors.New("whois error")
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "insecure: tailscale whois no profile",
			handler: insecureFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{Node: &tailcfg.Node{Tags: []string{"foo"}}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "insure: tailscale whois no node",
			handler: insecureFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login"}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "insecure: tagged node",
			handler: insecureFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"foo"}}}, nil
			},
			wantNext:   true,
			wantStatus: http.StatusOK,
			wantBody:   "OK",
			wantHeaders: map[string]string{
				"X-Webauth-User": "",
				"X-Webauth-Name": "",
			},
		},
		{
			name:    "insecure: user node",
			handler: insecureFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login", DisplayName: "name"}, Node: &tailcfg.Node{Name: "login.ts.net"}}, nil
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Unauthorized",
		},
		{
			name:    "oidc: tailscale whois error",
			handler: oidcFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return nil, errors.New("whois error")
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "oidc: tailscale whois no profile",
			handler: oidcFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{Node: &tailcfg.Node{Tags: []string{"foo"}}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "oidc: tailscale whois no node",
			handler: oidcFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login"}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name:    "oidc: user node",
			handler: oidcFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login", DisplayName: "name"}, Node: &tailcfg.Node{Name: "login.ts.net"}}, nil
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Unauthorized",
		},
		{
			name:    "oidc: tagged node",
			handler: oidcFunnel,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"tag:ingress"}}}, nil
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Unauthorized",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var nextReq *http.Request
			h := tc.handler(logger, &fakeLocalClient{whois: tc.whois}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextReq = r
				fmt.Fprintf(w, "OK")
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example.com/path", nil))
			resp := w.Result()

			if want, got := tc.wantStatus, resp.StatusCode; want != got {
				t.Errorf("want status %d, got: %d", want, got)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), tc.wantBody) {
				t.Errorf("want body %q, got: %q", tc.wantBody, string(body))
			}
			if tc.wantNext && nextReq == nil {
				t.Fatalf("next handler not called")
			}
			for k, want := range tc.wantHeaders {
				if got := nextReq.Header.Get(k); got != want {
					t.Errorf("want header %s = %s, got: %s", k, want, got)
				}
			}
		})
	}
}

func TestRedirectHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		forceSSL     bool
		fqdn         string
		request      *http.Request
		wantNext     bool
		wantStatus   int
		wantLocation string
	}{
		{
			name:         "forceSSL: redirect",
			forceSSL:     true,
			fqdn:         "http://example.com",
			request:      httptest.NewRequest("", "/path", nil),
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.com/path",
		},
		{
			name:       "forceSSL: ok",
			forceSSL:   true,
			fqdn:       "example.com",
			request:    httptest.NewRequest("", "https://example.com/path", nil),
			wantNext:   true,
			wantStatus: http.StatusOK,
		},
		{
			name:         "fqdn: redirect",
			fqdn:         "example.ts.net",
			request:      httptest.NewRequest("", "https://example/path", nil),
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.ts.net/path",
		},
		{
			name:       "fqdn: ok",
			fqdn:       "example.ts.net",
			request:    httptest.NewRequest("", "https://example.ts.net/path", nil),
			wantNext:   true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "fqdn: ok (not tls)",
			fqdn:       "example.ts.net",
			request:    httptest.NewRequest("", "/path", nil),
			wantNext:   true,
			wantStatus: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var nextReq *http.Request
			h := redirect(tc.fqdn, tc.forceSSL, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextReq = r
				fmt.Fprintf(w, "OK")
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, tc.request)
			resp := w.Result()

			if want, got := tc.wantStatus, resp.StatusCode; want != got {
				t.Errorf("want status %d, got: %d", want, got)
			}

			if tc.wantNext && nextReq == nil {
				t.Fatalf("next handler not called")
			}
			if !tc.wantNext && nextReq != nil {
				t.Fatalf("next handler was called")
			}
			if nextReq != nil {
				if want, got := tc.wantLocation, nextReq.Header.Get("Location"); got != want {
					t.Errorf("want Location header %s, got: %s", want, got)
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
