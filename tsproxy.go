package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/exp/slog"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
)

type tailscaleLocalClient interface {
	WhoIs(context.Context, string) (*apitype.WhoIsResponse, error)
}

func tsWaitStatusReady(ctx context.Context, lc *tailscale.LocalClient) (*ipnstate.Status, error) {
	var st *ipnstate.Status

	err := backoff.Retry(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}

		loopCtx, cancel := context.WithTimeout(ctx, time.Second)
		var err error
		st, err = lc.Status(loopCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("get status: %w", err)
		}

		if st.BackendState != "Running" {
			return fmt.Errorf("backend not running: %s", st.BackendState)
		}
		if len(st.TailscaleIPs) != 2 {
			return fmt.Errorf("IPs not yet assigned")
		}
		return nil
	}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))
	if err != nil {
		return nil, err
	}
	return st, nil
}

func newReverseProxy(logger *slog.Logger, lc tailscaleLocalClient, url *url.URL) http.HandlerFunc {
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
		// TODO(sr) No tags?
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

func serveDiscovery(self string, targets []target) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tgs []string
		tgs = append(tgs, self)
		for _, t := range targets {
			if t.magicDNS == "" {
				continue
			}
			if !t.prometheus {
				continue
			}
			tgs = append(tgs, t.magicDNS)
		}
		sort.Strings(tgs)
		buf, err := json.Marshal([]struct {
			Targets []string `json:"targets"`
		}{
			{Targets: tgs},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(buf)
	})
}

func serveIndex(t *template.Template, targets []target) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tgs []string
		for _, t := range targets {
			if t.magicDNS == "" {
				continue
			}
			h, _, ok := strings.Cut(t.magicDNS, ".") // strip the magicDNS suffix.
			if !ok {
				continue
			}
			tgs = append(tgs, h)
		}
		sort.Strings(tgs)
		if err := t.Execute(w, tgs); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}
