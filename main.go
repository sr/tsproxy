package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"

	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/tailscale/hujson"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tsnet"
	tslogger "tailscale.com/types/logger"
)

var (
	requestsInFlight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "tsproxy",
			Name:      "requests_in_flight",
			Help:      "Number of requests currently being served by the server.",
		},
		[]string{"upstream"},
	)

	requests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tsproxy",
			Name:      "requests_total",
			Help:      "Number of requests received by the server.",
		},
		[]string{"upstream", "code", "method"},
	)

	duration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:                   "tsproxy",
			Name:                        "request_duration_seconds",
			Help:                        "A histogram of latencies for requests handled by the server.",
			NativeHistogramBucketFactor: 1.1,
		},
		[]string{"upstream", "code", "method"},
	)
)

type upstream struct {
	Name       string
	Backend    string
	Prometheus bool
	Funnel     bool
}

type target struct {
	name       string
	magicDNS   string
	prometheus bool
}

func main() {
	if err := tsproxy(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "tsproxy: %v\n", err)
		os.Exit(1)
	}
}

func tsproxy(ctx context.Context) error {
	var (
		state  = flag.String("state", "", "Optional directory for storing Tailscale state.")
		tslog  = flag.Bool("tslog", false, "If true, log Tailscale output.")
		port   = flag.Int("port", 32019, "HTTP port for metrics and service discovery.")
		ver    = flag.Bool("version", false, "print the version and exit")
		upfile = flag.String("upstream", "", "path to upstreams config file")
	)
	flag.Parse()

	if *ver {
		fmt.Fprintln(os.Stdout, version.Print("tsproxy"))
		os.Exit(0)
	}

	if *upfile == "" {
		return fmt.Errorf("required flag missing: upstream")
	}

	in, err := os.ReadFile(*upfile)
	if err != nil {
		return err
	}
	inJSON, err := hujson.Standardize(in)
	if err != nil {
		return fmt.Errorf("hujson: %w", err)
	}
	var upstreams []upstream
	if err := json.Unmarshal(inJSON, &upstreams); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	if len(upstreams) == 0 {
		return fmt.Errorf("file does not contain any upstreams: %s", *upfile)
	}

	if *state == "" {
		v, err := os.UserCacheDir()
		if err != nil {
			return err
		}
		dir := filepath.Join(v, "tsproxy")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		state = &dir
	}
	prometheus.MustRegister(versioncollector.NewCollector("tsproxy"))

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))
	slog.SetDefault(logger)

	// If tailscaled isn't ready yet, just crash.
	st, err := (&local.Client{}).Status(ctx)
	if err != nil {
		return fmt.Errorf("tailscale: get node status: %w", err)
	}
	if v := len(st.Self.TailscaleIPs); v != 2 {
		return fmt.Errorf("want 2 tailscale IPs, got %d", v)
	}

	// service discovery targets (self + all upstreams)
	targets := make([]target, len(upstreams)+1)

	var g run.Group
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.Add(run.SignalHandler(ctx, os.Interrupt, syscall.SIGTERM))

	{
		p := strconv.Itoa(*port)

		var listeners []net.Listener
		for _, ip := range st.Self.TailscaleIPs {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), p))
			if err != nil {
				return fmt.Errorf("listen on %s:%d: %w", ip, *port, err)
			}
			listeners = append(listeners, ln)
		}

		http.Handle("/metrics", promhttp.Handler())
		http.Handle("/sd", serveDiscovery(net.JoinHostPort(st.Self.DNSName, p), targets))
		http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<html>
				<head><title>tsproxy</title></head>
				<body>
				<h1>tsproxy</h1>
				<p><a href="/metrics">Metrics</a></p>
				<p><a href="/sd">Discovery</a></p>
				</body>
				</html>`))
		})

		srv := &http.Server{}
		for _, ln := range listeners {
			ln := ln
			g.Add(func() error {
				logger.Info("server ready", slog.String("addr", ln.Addr().String()))
				return srv.Serve(ln)
			}, func(_ error) {
				if err := srv.Close(); err != nil {
					logger.Error("shutdown server", lerr(err))
				}
				cancel()
			})
		}
	}

	for i, upstream := range upstreams {
		log := logger.With(slog.String("upstream", upstream.Name))

		ts := &tsnet.Server{
			Hostname:     upstream.Name,
			Dir:          filepath.Join(*state, "tailscale-"+upstream.Name),
			RunWebClient: true,
		}
		defer ts.Close()

		if *tslog {
			ts.Logf = func(format string, args ...any) {
				//nolint: sloglint
				log.Info(fmt.Sprintf(format, args...), slog.String("logger", "tailscale"))
			}
		} else {
			ts.Logf = tslogger.Discard
		}
		if err := os.MkdirAll(ts.Dir, 0o700); err != nil {
			return err
		}

		lc, err := ts.LocalClient()
		if err != nil {
			return fmt.Errorf("tailscale: get local client for %s: %w", upstream.Name, err)
		}

		backendURL, err := url.Parse(upstream.Backend)
		if err != nil {
			return fmt.Errorf("upstream %s: parse backend URL: %w", upstream.Name, err)
		}

		srv := &http.Server{
			TLSConfig: &tls.Config{GetCertificate: lc.GetCertificate},
			Handler: promhttp.InstrumentHandlerInFlight(requestsInFlight.With(prometheus.Labels{"upstream": upstream.Name}),
				promhttp.InstrumentHandlerDuration(duration.MustCurryWith(prometheus.Labels{"upstream": upstream.Name}),
					promhttp.InstrumentHandlerCounter(requests.MustCurryWith(prometheus.Labels{"upstream": upstream.Name}),
						newReverseProxy(log, lc, backendURL)))),
		}

		g.Add(func() error {
			st, err := ts.Up(ctx)
			if err != nil {
				return fmt.Errorf("tailscale: wait for node %s to be ready: %w", upstream.Name, err)
			}

			// register in service discovery when we're ready.
			targets[i] = target{name: upstream.Name, prometheus: upstream.Prometheus, magicDNS: st.Self.DNSName}

			ln, err := ts.Listen("tcp", ":80")
			if err != nil {
				return fmt.Errorf("tailscale: listen for %s on port 80: %w", upstream.Name, err)
			}
			return srv.Serve(ln)
		}, func(_ error) {
			if err := srv.Close(); err != nil {
				log.Error("server shutdown", lerr(err))
			}
			cancel()
		})
		g.Add(func() error {
			_, err := ts.Up(ctx)
			if err != nil {
				return fmt.Errorf("tailscale: wait for node %s to be ready: %w", upstream.Name, err)
			}

			if upstream.Funnel {
				ln, err := ts.ListenFunnel("tcp", ":443")
				if err != nil {
					return fmt.Errorf("tailscale: funnel for %s on port 443: %w", upstream.Name, err)
				}
				return srv.Serve(ln)
			}

			ln, err := ts.Listen("tcp", ":443")
			if err != nil {
				return fmt.Errorf("tailscale: listen for %s on port 443: %w", upstream.Name, err)
			}
			return srv.ServeTLS(ln, "", "")
		}, func(_ error) {
			if err := srv.Close(); err != nil {
				log.Error("TLS server shutdown", lerr(err))
			}
			cancel()
		})
	}

	return g.Run()
}

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
	rproxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
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

		if whois.Node == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("tailscale whois", slog.String("err", "node missing"))
			return
		}

		if whois.UserProfile == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("tailscale whois", slog.String("err", "user profile missing"))
			return
		}

		// Proxy requests from tagged nodes as is.
		if whois.Node.IsTagged() {
			rproxy.ServeHTTP(w, r)
			return
		}

		req := r.Clone(r.Context())
		req.Header.Set("X-Webauth-User", whois.UserProfile.LoginName)
		req.Header.Set("X-Webauth-Name", whois.UserProfile.DisplayName)
		rproxy.ServeHTTP(w, req)
	})
}

func serveDiscovery(self string, targets []target) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
