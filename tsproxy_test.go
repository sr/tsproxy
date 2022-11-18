package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/exp/slog"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type fakeLocalClient struct {
	whois func(context.Context, string) (*apitype.WhoIsResponse, error)
}

func (c *fakeLocalClient) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return c.whois(ctx, remoteAddr)
}

func TestNewReverseProxy(t *testing.T) {
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
			want: http.StatusForbidden,
		},
		{
			name: "tailscale whois no profile",
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{}, nil
			},
			want: http.StatusForbidden,
		},
		{
			name: "tailscale whois ok",
			whois: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: "user", DisplayName: "user"}}, nil
			},
			want: http.StatusOK,
			wantHeaders: map[string]string{
				"X-Webauth-User": "user",
				"X-Webauth-Name": "user",
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
			px := httptest.NewServer(tsSingleHostReverseProxy(slog.New(slog.NewTextHandler(io.Discard)), lc, beURL))
			defer px.Close()

			resp, err := http.Get(px.URL)
			if err != nil {
				t.Fatal(err)
			}
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

func TestNewTSProxyHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		h    http.Handler
		req  *http.Request
		want *http.Response
	}{
		{
			name: "no tls",
			h:    tsReverseProxy(nil, nil, nil, ""),
			req:  &http.Request{},
			want: &http.Response{StatusCode: http.StatusInternalServerError},
		},
		{
			name: "upstream not found",
			h:    tsReverseProxy(nil, nil, nil, ""),
			req:  &http.Request{TLS: &tls.ConnectionState{ServerName: "example.com"}},
			want: &http.Response{StatusCode: http.StatusNotFound},
		},
		{
			name: "upstream found",
			h:    tsReverseProxy(map[string]http.Handler{"example.com": http.RedirectHandler("http://redirect.net", http.StatusMovedPermanently)}, nil, nil, ""),
			req:  &http.Request{TLS: &tls.ConnectionState{ServerName: "example.com"}},
			want: &http.Response{StatusCode: http.StatusMovedPermanently, Header: http.Header{"Location": []string{"http://redirect.net"}}},
		},
		{
			name: "self not found",
			h:    tsReverseProxy(map[string]http.Handler{"example.com": http.RedirectHandler("http://redirect.net", http.StatusMovedPermanently)}, nil, nil, "example.com"),
			req:  &http.Request{RequestURI: "/", TLS: &tls.ConnectionState{ServerName: "example.com"}},
			want: &http.Response{StatusCode: http.StatusNotFound},
		},
		{
			name: "self metrics",
			h:    tsReverseProxy(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintf(w, "metrics") }), nil, "example.com"),
			req:  &http.Request{RequestURI: "/metrics", TLS: &tls.ConnectionState{ServerName: "example.com"}},
			want: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("metrics")))},
		},
		{
			name: "self service discovery",
			h:    tsReverseProxy(nil, nil, []string{"localhost:8000"}, "example.com"),
			req:  &http.Request{RequestURI: "/sd", TLS: &tls.ConnectionState{ServerName: "example.com"}},
			want: &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{`application/json; charset=utf-8`}}, Body: io.NopCloser(bytes.NewReader([]byte(`[{"targets":["localhost:8000"]}]`)))},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRecorder()
			tc.h.ServeHTTP(r, tc.req)
			resp := r.Result()
			if want, got := tc.want.StatusCode, resp.StatusCode; want != got {
				t.Errorf("want status %d, got: %d", want, got)
			}
			if len(tc.want.Header) > 0 {
				if diff := cmp.Diff(tc.want.Header, resp.Header); diff != "" {
					t.Errorf("headers mismatch (-want +got):\n%s", diff)
				}
			}
			if tc.want.Body != nil {
				want, err := io.ReadAll(tc.want.Body)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(string(want), string(got)); diff != "" {
					t.Errorf("body mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()

	lint, err := testutil.GatherAndLint(prometheus.DefaultGatherer)
	if err != nil {
		t.Fatalf("CollectAndLint: %v", err)
	}
	for _, prob := range lint {
		t.Errorf("lint: %s: %s", prob.Metric, prob.Text)
	}
	if len(lint) > 0 {
		t.Fatal("lint problems detected")
	}
}
