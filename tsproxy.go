package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"

	"golang.org/x/exp/slog"
	"tailscale.com/client/tailscale/apitype"
)

type tailscaleLocalClient interface {
	WhoIs(context.Context, string) (*apitype.WhoIsResponse, error)
}

func tsSingleHostReverseProxy(logger *slog.Logger, lc tailscaleLocalClient, url *url.URL) http.Handler {
	// TODO(sr) Instrument proxy.Transport
	proxy := httputil.NewSingleHostReverseProxy(url)
	orig := proxy.Director
	proxy.Director = func(req *http.Request) {
		orig(req)

		whois, err := lc.WhoIs(req.Context(), req.RemoteAddr)
		if err != nil {
			logger.Error("tailscale whois", err)
			return
		}
		if whois.UserProfile == nil {
			logger.Error("tailscale whois", errors.New("response did not include a user profile"))
			return
		}
		req.Header.Set("X-Webauth-User", whois.UserProfile.LoginName)
		req.Header.Set("X-Webauth-Name", whois.UserProfile.DisplayName)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.Director(r)
		if r.Header.Get("X-Webauth-User") == "" || r.Header.Get("X-Webauth-Name") == "" {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func tsReverseProxy(rpx map[string]http.Handler, metrics http.Handler, targets []string, self string) http.Handler {
	sort.Strings(targets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if r.TLS.ServerName == self {
			if r.RequestURI == "/sd" {
				resp := []struct {
					Targets []string `json:"targets"`
				}{
					{Targets: targets},
				}
				buf, err := json.Marshal(resp)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, _ = w.Write(buf)
				return
			}
			if r.RequestURI == "/metrics" {
				metrics.ServeHTTP(w, r)
				return
			}
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		px, ok := rpx[r.TLS.ServerName]
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		px.ServeHTTP(w, r)
	})
}
