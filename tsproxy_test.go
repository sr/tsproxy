package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/tailscale/hujson"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
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

	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{}))

	for _, tc := range []struct {
		name        string
		whois       func(context.Context, string) (*apitype.WhoIsResponse, error)
		handler     func(*slog.Logger, tailscaleLocalClient, *vm.Program, http.Handler) http.Handler
		expr        string
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
			name:    "tailnet: tailscale whois ok (user, no expr)",
			handler: tailnet,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login", DisplayName: "name"}, Node: &tailcfg.Node{Name: "login.ts.net"}}, nil
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
			name:    "tailnet: tailscale whois ok (user, expr set)",
			handler: tailnet,
			expr:    `{user: "user", name: "name"}`,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login", DisplayName: "name"}, Node: &tailcfg.Node{Name: "login.ts.net"}}, nil
			},
			wantNext:   true,
			wantStatus: http.StatusOK,
			wantBody:   "OK",
			wantHeaders: map[string]string{
				"X-Webauth-User": "user",
				"X-Webauth-Name": "name",
			},
		},
		{
			name:    "tailnet: tailscale whois ok (user, expr set, vars)",
			handler: tailnet,
			expr:    `{user: tailscale.LoginName, name: tailscale.DisplayName}`,
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
			name:    "tailnet: tailscale whois ok (user, bad expr)",
			handler: tailnet,
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login", DisplayName: "name"}, Node: &tailcfg.Node{Name: "login.ts.net"}}, nil
			},
			expr:       `{user: false}`,
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
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
			name: "oidc: tailscale whois error",
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				return oidcFunnel(logger, lc, nil, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return nil, errors.New("whois error")
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name: "oidc: tailscale whois no profile",
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				return oidcFunnel(logger, lc, nil, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{Node: &tailcfg.Node{Tags: []string{"foo"}}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name: "oidc: tailscale whois no node",
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				return oidcFunnel(logger, lc, nil, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login"}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name: "oidc: user node",
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				return oidcFunnel(logger, lc, nil, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "login", DisplayName: "name"}, Node: &tailcfg.Node{Name: "login.ts.net"}}, nil
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Unauthorized",
		},
		{
			name: "oidc: tagged node, no token",
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				return oidcFunnel(logger, lc, func(_ context.Context) (*jwt.VerifiedJWT, bool) { return nil, false }, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"tag:ingress"}}}, nil
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Unauthorized",
		},
		{
			name: "oidc: tagged node, verified token, expr not set",
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				sub := "sub"
				exp := time.Now().Add(time.Hour)
				return oidcFunnel(logger, lc, func(_ context.Context) (*jwt.VerifiedJWT, bool) {
					return verifiedJWT(t, &jwt.RawJWTOptions{Issuer: &sub, Subject: &sub, ExpiresAt: &exp}), true
				}, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"tag:ingress"}}}, nil
			},
			wantStatus: http.StatusOK,
			wantBody:   "OK",
			wantNext:   true,
		},
		{
			name: "oidc: tagged node, verified token, expr set",
			expr: `{user: oidc.Sub}`,
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				sub := "sub"
				exp := time.Now().Add(time.Hour)
				return oidcFunnel(logger, lc, func(_ context.Context) (*jwt.VerifiedJWT, bool) {
					return verifiedJWT(t, &jwt.RawJWTOptions{Issuer: &sub, Subject: &sub, ExpiresAt: &exp}), true
				}, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"tag:ingress"}}}, nil
			},
			wantStatus: http.StatusOK,
			wantBody:   "OK",
			wantNext:   true,
			wantHeaders: map[string]string{
				"X-Webauth-User": "sub",
			},
		},
		{
			name: "oidc: tagged node, verified token, bad expr",
			expr: `{user: false}`,
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				sub := "sub"
				exp := time.Now().Add(time.Hour)
				return oidcFunnel(logger, lc, func(_ context.Context) (*jwt.VerifiedJWT, bool) {
					return verifiedJWT(t, &jwt.RawJWTOptions{Issuer: &sub, Subject: &sub, ExpiresAt: &exp}), true
				}, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"tag:ingress"}}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name: "oidc: tagged node, verified token, empty string map key",
			expr: `{"": "val"}`,
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				sub := "sub"
				exp := time.Now().Add(time.Hour)
				return oidcFunnel(logger, lc, func(_ context.Context) (*jwt.VerifiedJWT, bool) {
					return verifiedJWT(t, &jwt.RawJWTOptions{Issuer: &sub, Subject: &sub, ExpiresAt: &exp}), true
				}, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"tag:ingress"}}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
		{
			name: "oidc: tagged node, verified token, empty string map value",
			expr: `{user: ""}`,
			handler: func(logger *slog.Logger, lc tailscaleLocalClient, prog *vm.Program, next http.Handler) http.Handler {
				sub := "sub"
				exp := time.Now().Add(time.Hour)
				return oidcFunnel(logger, lc, func(_ context.Context) (*jwt.VerifiedJWT, bool) {
					return verifiedJWT(t, &jwt.RawJWTOptions{Issuer: &sub, Subject: &sub, ExpiresAt: &exp}), true
				}, prog, next)
			},
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"}, Node: &tailcfg.Node{Tags: []string{"tag:ingress"}}}, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal Server Error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				prog *vm.Program
				err  error
			)
			if tc.expr != "" {
				prog, err = expr.Compile(tc.expr, expr.AsKind(reflect.Map))
				if err != nil {
					t.Fatalf("compile expr: %v", err)
				}
			}

			var nextReq *http.Request
			h := tc.handler(logger, &fakeLocalClient{whois: tc.whois}, prog, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if !tc.wantNext && nextReq != nil {
				t.Fatalf("next handler should not have been called")
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
				t.Fatalf("next handler was not called")
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

func TestBasicAuthHandler(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))

	for _, tc := range []struct {
		name       string
		user       string
		password   string
		request    func(*http.Request)
		wantNext   bool
		wantStatus int
	}{
		{
			name:       "no basic auth provided",
			user:       "admin",
			password:   "secret",
			request:    func(_ *http.Request) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong user",
			user:       "admin",
			password:   "secret",
			request:    func(r *http.Request) { r.SetBasicAuth("bad", "secret") },
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong password",
			user:       "admin",
			password:   "secret",
			request:    func(r *http.Request) { r.SetBasicAuth("admin", "bad") },
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ok",
			user:       "admin",
			password:   "secret",
			request:    func(r *http.Request) { r.SetBasicAuth("admin", "secret") },
			wantNext:   true,
			wantStatus: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var nextReq *http.Request
			h := basicAuth(logger, tc.user, tc.password, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextReq = r
				fmt.Fprintf(w, "OK")
			}))
			w := httptest.NewRecorder()
			req := httptest.NewRequest("", "/", nil)
			tc.request(req)
			h.ServeHTTP(w, req)
			resp := w.Result()

			if want, got := tc.wantStatus, resp.StatusCode; want != got {
				t.Errorf("want status %d, got: %d", want, got)
			}

			if tc.wantNext && nextReq == nil {
				t.Fatalf("next handler not called")
			}
			if !tc.wantNext && nextReq != nil {
				t.Fatalf("next handler should not have been called")
			}
		})
	}
}

func TestStripAuthHeadersHandler(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("", "/", nil)
	req.Header.Add("x-webauth-user", "user")
	req.Header.Add("x-webauth-magic", "value")

	stripAuthHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WEBAUTH-USER") != "" {
			t.Fatalf("X-WEBAUTH header still present")
		}
		if r.Header.Get("X-WEBAUTH-MAGIC") != "" {
			t.Fatalf("X-WEBAUTH header still present")
		}
		fmt.Fprintf(w, "OK")
	})).ServeHTTP(w, req)
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

func TestSetAuthHeader(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		expr        string
		env         exprEnv
		wantErr     error
		wantHeaders map[string]string
	}{
		{
			name:    "bad expr",
			env:     exprEnv{ID: &idClaims{Sub: "sub"}},
			expr:    "{foo: false}",
			wantErr: errors.New("did not return map"),
		},
		{
			name: "ok expr",
			env:  exprEnv{ID: &idClaims{Sub: "sub"}},
			expr: "{user: oidc.Sub}",
			wantHeaders: map[string]string{
				"X-Webauth-User": "sub",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prog, err := expr.Compile(tc.expr, expr.Env(exprEnv{}), expr.AsKind(reflect.Map))
			if err != nil {
				t.Fatal(err)
			}

			req, err := setAuthHeader(prog, tc.env, httptest.NewRequest("GET", "/", nil))
			if err != nil {
				if tc.wantErr == nil || !strings.Contains(err.Error(), tc.wantErr.Error()) {
					t.Fatalf("got unexpected err: %v (want: %v)", err, tc.wantErr)
				}
			} else if tc.wantErr != nil {
				t.Fatalf("expected err %v, got none", tc.wantErr)
			}
			for k, want := range tc.wantHeaders {
				if got := req.Header.Get(k); got != want {
					t.Errorf("want header %s = %s, got: %s", k, want, got)
				}
			}
		})
	}
}

func verifiedJWT(t *testing.T, rawOpts *jwt.RawJWTOptions) *jwt.VerifiedJWT {
	t.Helper()

	h, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatal(err)
	}

	pub, err := h.Public()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner(h)
	if err != nil {
		t.Fatal(err)
	}

	r, err := jwt.NewRawJWT(rawOpts)
	if err != nil {
		t.Fatal(err)
	}

	c, err := signer.SignAndEncode(r)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := jwt.NewVerifier(pub)
	if err != nil {
		t.Fatalf("HERE: %v", err)
	}

	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:  rawOpts.Issuer,
		IgnoreAudiences: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	verified, err := verifier.VerifyAndDecode(c, validator)
	if err != nil {
		t.Fatal(err)
	}

	return verified
}

//go:embed example.json
var example []byte

func TestExampleConfig(t *testing.T) {
	inJSON, err := hujson.Standardize(example)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(inJSON))
	dec.DisallowUnknownFields()
	var upstreams []upstream
	if err := dec.Decode(&upstreams); err != nil {
		t.Fatal(err)
	}
}
