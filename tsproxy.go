package main

import (
	"context"
	"encoding/json"
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
		logger.Error("upstream error", lerr(err))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		whois, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("tailscale whois", lerr(err))
			return
		}

		// TODO(sr) Forbid access to tagged users (i.e. machines)?
		if whois.UserProfile == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("tailscale whois", slog.String("err", "user profile missing"))
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

func lerr(err error) slog.Attr {
	return slog.String("err", err.Error())
}
