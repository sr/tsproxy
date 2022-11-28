package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sr/tsproxy/internal/autocert"

	"github.com/cenkalti/backoff/v4"
	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/exp/slog"
	"golang.org/x/oauth2"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	tslogger "tailscale.com/types/logger"
)

const (
	// 5 minutes TTL.
	dnsTTL = 5 * 60

	// keep this below systemd's DefaultTimeoutStopSec (90 seconds)
	stopTimeout = 80 * time.Second
)

var (
	requestsInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "tsproxy",
		Name:      "requests_in_flight",
		Help:      "Number of requests currently being served by the server.",
	})

	requests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tsproxy",
			Name:      "requests_total",
			Help:      "Number of requests received by the server.",
		},
		[]string{"code", "method"},
	)

	duration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:                   "tsproxy",
			Name:                        "request_duration_seconds",
			Help:                        "A histogram of latencies for requests handled by the server.",
			NativeHistogramBucketFactor: 1.1,
		},
		[]string{"code", "method"},
	)
)

type upstreamFlag []upstream

func (f *upstreamFlag) String() string {
	return fmt.Sprintf("%+v", *f)
}

func (f *upstreamFlag) Set(val string) error {
	up, err := parseUpstreamFlag(val)
	if err != nil {
		return err
	}
	*f = append(*f, up)
	return nil
}

type upstream struct {
	name       string
	backend    *url.URL
	prometheus bool
}

func fqdn(zone, name string) string {
	return name + "." + zone
}

func parseUpstreamFlag(fval string) (upstream, error) {
	kv := strings.Split(fval, "=")
	if len(kv) != 2 {
		return upstream{}, errors.New("format: name=http://backend")
	}
	val := strings.Split(kv[1], ";")
	be, err := url.Parse(val[0])
	if err != nil {
		return upstream{}, err
	}
	up := upstream{name: kv[0], backend: be}
	if len(val) > 1 {
		for _, opt := range val[1:] {
			switch opt {
			case "prometheus":
				up.prometheus = true
			default:
				return upstream{}, fmt.Errorf("unsupported option: %v", opt)
			}
		}
	}
	return up, nil
}

func main() {
	if err := tsproxy(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "tsproxy: %v\n", err)
		os.Exit(1)
	}
}

func tsproxy(ctx context.Context) error {
	var (
		tok      = flag.String("access-token", "", "DNSimple API Access Token. (Environment: DNSIMPLE_ACCESS_TOKEN)")
		zone     = flag.String("zone", "", "DNSimple Zone.")
		email    = flag.String("email", "", "Optional ACME registration email.")
		state    = flag.String("state", "", "Optional directory for storing Tailscale and autocert state.")
		hostname = flag.String("hostname", os.Getenv("HOSTNAME"), "Tailscale machine name.")
		tslog    = flag.Bool("tailscale-logger", false, "If true, log Tailscale output.")
	)
	var ups upstreamFlag
	flag.Var(&ups, "upstream", "Repeated for each upstream. Format: name=http://backend:8000")
	flag.Parse()

	if v := os.Getenv("DNSIMPLE_ACCESS_TOKEN"); v != "" {
		tok = &v
	}
	if *tok == "" {
		return fmt.Errorf("required flag missing: access-token")
	}
	if *zone == "" {
		return fmt.Errorf("required flag missing: zone")
	}
	if len(ups) == 0 {
		return fmt.Errorf("required flag missing: upstream")
	}
	if *state == "" {
		v, err := os.UserCacheDir()
		if err != nil {
			return err
		}
		dir := filepath.Join(v, "tsproxy")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		state = &dir
	}
	if *hostname == "" {
		if v, err := os.Hostname(); err == nil {
			hostname = &v
		} else {
			return fmt.Errorf("required flag missing: hostname")
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr))

	dnscli := dnsimple.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *tok})))
	resp, err := dnscli.Identity.Whoami(ctx)
	if err != nil {
		return fmt.Errorf("dnsimple: whoami request: %w", err)
	}
	aid := strconv.FormatInt(resp.Data.Account.ID, 10)

	// This is our DNS name. It will resolve to our tailscale IPs (A and AAAA records).
	self := fqdn(*zone, strings.ToLower(*hostname))

	cache := filepath.Join(*state, "autocert")
	acm := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cache),
		Email:  *email,
		DNS01:  dnsimpleDNS01Solver(logger, dnscli.Zones, aid, *zone),
	}
	var names []string
	for _, u := range ups {
		names = append(names, fqdn(*zone, u.name))
	}
	names = append(names, self)
	acm.HostPolicy = autocert.HostWhitelist(names...)

	if err := os.MkdirAll(cache, 0700); err != nil {
		return err
	}

	ts := &tsnet.Server{
		Hostname: strings.ToLower(*hostname),
		Dir:      filepath.Join(*state, "tailscale"),
	}
	if *tslog {
		ts.Logf = func(format string, args ...any) {
			logger.LogAttrs(slog.InfoLevel, fmt.Sprintf(format, args...), slog.String("logger", "tailscale"))
		}
	} else {
		ts.Logf = tslogger.Discard
	}
	if err := os.MkdirAll(ts.Dir, 0700); err != nil {
		return err
	}
	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("tailscale: init local client: %w", err)
	}
	// ts.LocalClient() implicitly starts the server, make sure it gets closed.
	defer ts.Close()

	var st *ipnstate.Status
	err = backoff.Retry(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}

		loopCtx, cancel := context.WithTimeout(ctx, time.Second)
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
		return fmt.Errorf("tailscale: wait for backend to be ready: %w", err)
	}

	var g run.Group
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.Add(run.SignalHandler(ctx, os.Interrupt, syscall.SIGTERM))
	{
		var (
			// SingleHostReverseProxy for each upstream.
			rpx = make(map[string]http.Handler)

			// targets returned by the http_sd discovery endpoint.
			targets []string
		)
		for _, u := range ups {
			fqdn := fqdn(*zone, u.name)

			rpx[fqdn] = tsSingleHostReverseProxy(logger, lc, u.backend)
			if u.prometheus {
				targets = append(targets, fqdn)
			}
		}
		// Add self to service discovery.
		targets = append(targets, self)

		srv := &http.Server{
			TLSConfig: &tls.Config{GetCertificate: acm.GetCertificate},
			Handler: promhttp.InstrumentHandlerInFlight(requestsInFlight,
				promhttp.InstrumentHandlerDuration(duration,
					promhttp.InstrumentHandlerCounter(requests,
						tsReverseProxy(rpx, promhttp.Handler(), targets, self)))),
		}

		g.Add(func() error {
			ln, err := ts.Listen("tcp", ":443")
			if err != nil {
				return fmt.Errorf("tailscale listen on :443: %w", err)
			}
			defer ln.Close()
			logger.Info("proxy server ready", slog.String("addr", ln.Addr().String()))
			return srv.ServeTLS(ln, "", "")
		}, func(err error) {
			defer cancel()

			logger.Info("shutting down proxy server")
			shutdownCtx, cancel := context.WithTimeout(ctx, stopTimeout)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				logger.Error("proxy server shutdown", err)
			}
		})
	}
	{
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Strip the port.
				var host string
				if h, _, err := net.SplitHostPort(r.Host); err != nil {
					host = r.Host
				} else {
					host = h
				}
				http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			}),
		}
		g.Add(func() error {
			ln, err := ts.Listen("tcp", ":80")
			if err != nil {
				return fmt.Errorf("tailscale listen on :80: %w", err)
			}
			defer ln.Close()
			logger.Info("HTTPS redirect server ready", slog.String("addr", ln.Addr().String()))
			return srv.Serve(ln)
		}, func(err error) {
			defer cancel()
			if err := srv.Close(); err != nil {
				logger.Error("shutdown HTTPS redirect server", err)
			}
		})
	}

	// Configure DNS in the background.
	go func() {
		start := time.Now()
		if err := configureDNS(ctx, dnscli.Zones, net.DefaultResolver, aid, *zone, ups, st.TailscaleIPs, ts.Hostname); err != nil {
			logger.Error("configure DNS", err)
		} else {
			logger.Info("DNS configured", slog.Duration("timer", time.Since(start)))
		}
	}()

	return fmt.Errorf("server group exited: %w", g.Run())
}
