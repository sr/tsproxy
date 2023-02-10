package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"time"

	"golang.org/x/exp/slog"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
)

type tailscaleLocalClient interface {
	WhoIs(context.Context, string) (*apitype.WhoIsResponse, error)
}

func tsWaitStatusReady(ctx context.Context, logger *slog.Logger, lc *tailscale.LocalClient) (*ipnstate.Status, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		loopCtx, cancel := context.WithTimeout(ctx, time.Second)
		st, err := lc.Status(loopCtx)
		cancel()
		if err != nil {
			logger.Error("get tailscale status", err)
			continue
		}

		if st.BackendState == "Running" && len(st.TailscaleIPs) == 2 {
			return st, nil
		}
		logger.Info("waiting for tailscale backend to be ready", slog.String("state", st.BackendState), slog.Int("IPs", len(st.TailscaleIPs)), slog.String("authURL", st.AuthURL))
		time.Sleep(time.Second)
	}
}

func newReverseProxy(logger *slog.Logger, lc tailscaleLocalClient, url *url.URL) http.HandlerFunc {
	// TODO(sr) Instrument proxy.Transport
	rproxy := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(url)
			req.SetXForwarded()
			req.Out.Host = req.In.Host
		},
	}
	rproxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		logger.Error("upstream error", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		whois, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("tailscale whois", err)
			return
		}

		// TODO(sr) Forbid access to tagged users (i.e. machines)?
		if whois.UserProfile == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("tailscale whois", errors.New("user profile missing"))
			return
		}

		req := r.Clone(r.Context())
		req.Header.Set("X-Webauth-User", whois.UserProfile.LoginName)
		req.Header.Set("X-Webauth-Name", whois.UserProfile.DisplayName)

		rproxy.ServeHTTP(w, req)
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
