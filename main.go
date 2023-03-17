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

	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/exp/slog"
	"tailscale.com/client/tailscale"
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
	funnel     bool
}

type target struct {
	name       string
	magicDNS   string
	prometheus bool
}

func parseUpstreamFlag(fval string) (upstream, error) {
	k, v, ok := strings.Cut(fval, "=")
	if !ok {
		return upstream{}, errors.New("format: name=http://backend")
	}
	val := strings.Split(v, ";")
	be, err := url.Parse(val[0])
	if err != nil {
		return upstream{}, err
	}
	up := upstream{name: k, backend: be}
	if len(val) > 1 {
		for _, opt := range val[1:] {
			switch opt {
			case "prometheus":
				up.prometheus = true
			case "funnel":
				up.funnel = true
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
		state = flag.String("state", "", "Optional directory for storing Tailscale state.")
		tslog = flag.Bool("tslog", false, "If true, log Tailscale output.")
		port  = flag.Int("port", 32019, "HTTP port for metrics and service discovery.")
	)
	var upstreams upstreamFlag
	flag.Var(&upstreams, "upstream", "Repeated for each upstream. Format: name=http://backend:8000")
	flag.Parse()

	if len(upstreams) == 0 {
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

	logger := slog.New((slog.HandlerOptions{}).NewJSONHandler(os.Stderr))
	slog.SetDefault(logger)

	// If tailscaled isn't ready yet, just crash.
	st, err := (&tailscale.LocalClient{}).Status(ctx)
	if err != nil {
		return fmt.Errorf("tailscale: get node status: %w", err)
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
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
			}, func(err error) {
				if err := srv.Close(); err != nil {
					logger.Error("shutdown server", lerr(err))
				}
				cancel()
			})
		}
	}

	for i, upstream := range upstreams {
		// https://go.dev/doc/faq#closures_and_goroutines
		i := i
		upstream := upstream

		log := logger.With(slog.String("upstream", upstream.name))

		ts := &tsnet.Server{
			Hostname: upstream.name,
			Dir:      filepath.Join(*state, "tailscale-"+upstream.name),
		}
		defer ts.Close()

		if *tslog {
			ts.Logf = func(format string, args ...any) {
				log.Info(fmt.Sprintf(format, args...), slog.String("logger", "tailscale"))
			}
		} else {
			ts.Logf = tslogger.Discard
		}
		if err := os.MkdirAll(ts.Dir, 0700); err != nil {
			return err
		}

		lc, err := ts.LocalClient()
		if err != nil {
			return fmt.Errorf("tailscale: get local client for %s: %w", upstream.name, err)
		}

		srv := &http.Server{
			TLSConfig: &tls.Config{GetCertificate: lc.GetCertificate},
			Handler: promhttp.InstrumentHandlerInFlight(requestsInFlight.With(prometheus.Labels{"upstream": upstream.name}),
				promhttp.InstrumentHandlerDuration(duration.MustCurryWith(prometheus.Labels{"upstream": upstream.name}),
					promhttp.InstrumentHandlerCounter(requests.MustCurryWith(prometheus.Labels{"upstream": upstream.name}),
						newReverseProxy(log.With(slog.String("upstream", upstream.name)), lc, upstream.backend)))),
		}

		g.Add(func() error {
			st, err := ts.Up(ctx)
			if err != nil {
				return fmt.Errorf("tailscale: wait for node %s to be ready: %w", upstream.name, err)
			}

			// register in service discovery when we're ready.
			targets[i] = target{name: upstream.name, prometheus: upstream.prometheus, magicDNS: st.Self.DNSName}

			ln, err := ts.Listen("tcp", ":80")
			if err != nil {
				return fmt.Errorf("tailscale: listen for %s on port 80: %w", upstream.name, err)
			}
			return srv.Serve(ln)
		}, func(err error) {
			if err := srv.Close(); err != nil {
				log.Error("server shutdown", lerr(err))
			}
			cancel()
		})
		g.Add(func() error {
			_, err := ts.Up(ctx)
			if err != nil {
				return fmt.Errorf("tailscale: wait for node %s to be ready: %w", upstream.name, err)
			}

			if upstream.funnel {
				ln, err := ts.ListenFunnel("tcp", ":443")
				if err != nil {
					return fmt.Errorf("tailscale: funnel for %s on port 443: %w", upstream.name, err)
				}
				return srv.Serve(ln)
			}

			ln, err := ts.Listen("tcp", ":443")
			if err != nil {
				return fmt.Errorf("tailscale: listen for %s on port 443: %w", upstream.name, err)
			}
			return srv.ServeTLS(ln, "", "")
		}, func(err error) {
			if err := srv.Close(); err != nil {
				log.Error("TLS server shutdown", lerr(err))
			}
			cancel()
		})
	}

	return g.Run()
}
