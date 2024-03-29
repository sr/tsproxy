package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
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
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: %s <path to config>", os.Args[0])
	}
	cfgb, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("reading config file %s: %w", os.Args[1], err)
	}
	cfg, err := parseAndValidateConfig(cfgb)
	if err != nil {
		return fmt.Errorf("reading config file %s: %w", os.Args[1], err)
	}

	if len(cfg.Upstreams) == 0 {
		return fmt.Errorf("required flag missing: upstream")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))
	slog.SetDefault(logger)

	// If tailscaled isn't ready yet, just crash.
	st, err := (&tailscale.LocalClient{}).Status(ctx)
	if err != nil {
		return fmt.Errorf("tailscale: get node status: %w", err)
	}
	if v := len(st.Self.TailscaleIPs); v != 2 {
		return fmt.Errorf("want 2 tailscale IPs, got %d", v)
	}

	// service discovery targets (self + all upstreams)
	targets := make([]target, len(cfg.Upstreams)+1)

	var g run.Group
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.Add(run.SignalHandler(ctx, os.Interrupt, syscall.SIGTERM))

	{
		p := strconv.Itoa(cfg.MetricsDiscoveryPort)

		var listeners []net.Listener
		for _, ip := range st.Self.TailscaleIPs {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), p))
			if err != nil {
				return fmt.Errorf("listen on %s:%d: %w", ip, cfg.MetricsDiscoveryPort, err)
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

	for i, upstream := range cfg.Upstreams {
		log := logger.With(slog.String("upstream", upstream.Name))

		backendURL, err := url.Parse(upstream.Backend)
		if err != nil {
			return fmt.Errorf("parsing backend url %s: %w", backendURL, err)
		}

		stateStore, err := stateStoreForUpstream(cfg, upstream.Name)
		if err != nil {
			return err
		}

		ts := &tsnet.Server{
			Hostname: upstream.Name,
			Store:    stateStore,
		}
		defer ts.Close()

		if cfg.LogTailscale {
			ts.Logf = func(format string, args ...any) {
				log.Info(fmt.Sprintf(format, args...), slog.String("logger", "tailscale"))
			}
		} else {
			ts.Logf = tslogger.Discard
		}

		lc, err := ts.LocalClient()
		if err != nil {
			return fmt.Errorf("tailscale: get local client for %s: %w", upstream.Name, err)
		}

		log.Info(fmt.Sprintf("backend %s upstream %#v", upstream.Name, backendURL))

		// newServers constructs a http.Server with the base middleware/config
		// in place.
		newServer := func(h http.Handler) *http.Server {
			return &http.Server{
				TLSConfig: &tls.Config{GetCertificate: lc.GetCertificate},
				Handler: promhttp.InstrumentHandlerInFlight(requestsInFlight.With(prometheus.Labels{"upstream": upstream.Name}),
					promhttp.InstrumentHandlerDuration(duration.MustCurryWith(prometheus.Labels{"upstream": upstream.Name}),
						promhttp.InstrumentHandlerCounter(requests.MustCurryWith(prometheus.Labels{"upstream": upstream.Name}),
							h))),
			}
		}

		httpInterruptFunc := func(ctx context.Context, cancel func(), svr **http.Server) func(error) {
			return func(error) {
				if (*svr) != nil {
					shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
					defer shutdownCancel()
					if err := (*svr).Shutdown(shutdownCtx); err != nil {
						log.Error("server shutdown", lerr(err))
					}
				}
				cancel()
			}
		}

		var (
			httpServer          *http.Server
			httpCtx, httpCancel = context.WithCancel(ctx)
		)

		g.Add(func() error {
			st, err := ts.Up(httpCtx)
			if err != nil {
				return fmt.Errorf("tailscale: wait for node %s to be ready: %w", upstream.Name, err)
			}

			go func() {
				<-httpCtx.Done()
				log.Info("http context done")
			}()

			// register in service discovery when we're ready.
			targets[i] = target{name: upstream.Name, prometheus: upstream.Prometheus, magicDNS: st.Self.DNSName}

			ln, err := ts.Listen("tcp", ":80")
			if err != nil {
				return fmt.Errorf("tailscale: listen for %s on port 80: %w", upstream.Name, err)
			}

			rp := newReverseProxy(log, lc, backendURL)

			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !upstream.Funnel {
					rp.ServeHTTP(w, r)
					return
				}

				// if here, we have a funnel service too. To keep urls
				// consistent between funnel and non-funnel access, force TLS.
				// We need the cert anyway for funnel. If accessed by the short
				// hostname though, just allow that through as that'd never map
				// to the funnel side.
				if len(strings.Split(r.Host, ".")) == 1 || r.URL.Scheme == "https" {
					rp.ServeHTTP(w, r)
					return
				}

				http.Redirect(w, r, fmt.Sprintf("https://%s%s", strings.TrimSuffix(st.Self.DNSName, "."), r.RequestURI), http.StatusMovedPermanently)
			})

			httpServer = newServer(h)

			return httpServer.Serve(ln)
		}, httpInterruptFunc(httpCtx, httpCancel, &httpServer))

		var (
			httpsServer           *http.Server
			httpsCtx, httpsCancel = context.WithCancel(ctx)
		)

		g.Add(func() error {
			_, err := ts.Up(httpsCtx)
			if err != nil {
				return fmt.Errorf("tailscale: wait for node %s to be ready: %w", upstream.Name, err)
			}

			go func() {
				<-httpsCtx.Done()
				log.Info("https context done")
			}()

			ln, err := ts.Listen("tcp", ":443")
			if err != nil {
				return fmt.Errorf("tailscale: listen for %s on port 443: %w", upstream.Name, err)
			}

			httpsServer = newServer(newReverseProxy(log, lc, backendURL))

			return httpsServer.ServeTLS(ln, "", "")
		}, httpInterruptFunc(httpsCtx, httpsCancel, &httpsServer))

		if upstream.Funnel {
			var (
				funnelServer            *http.Server
				funnelCtx, funnelCancel = context.WithCancel(ctx)
			)

			g.Add(func() error {
				_, err := ts.Up(funnelCtx)
				if err != nil {
					return fmt.Errorf("tailscale: wait for node %s to be ready: %w", upstream.Name, err)
				}

				go func() {
					<-funnelCtx.Done()
					log.Info("funnel context done")
				}()

				ln, err := ts.ListenFunnel("tcp", ":443", tsnet.FunnelOnly())
				if err != nil {
					return fmt.Errorf("tailscale: funnel for %s on port 443: %w", upstream.Name, err)
				}

				rp := newReverseProxy(log, lc, backendURL)

				funnelServer = newServer(rp)

				return funnelServer.Serve(ln)
			}, httpInterruptFunc(funnelCtx, funnelCancel, &funnelServer))
		}
	}

	if err := g.Run(); err != nil {
		return fmt.Errorf("group run error: %w", err)
	}
	return nil
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

var clientset kubernetes.Interface

func stateStoreForUpstream(cfg config, upstreamName string) (ipn.StateStore, error) {
	if cfg.Kubernetes.Enabled {
		if clientset == nil {
			var kubeConfig *rest.Config
			if cfg.Kubernetes.KubeconfigPath != "" {
				c, err := clientcmd.BuildConfigFromFlags("", cfg.Kubernetes.KubeconfigPath)
				if err != nil {
					return nil, fmt.Errorf("building kubeconfig from %s: %w", cfg.Kubernetes.KubeconfigPath, err)
				}
				kubeConfig = c
			} else {
				c, err := rest.InClusterConfig()
				if err != nil {
					return nil, fmt.Errorf("building in-cluster kubeconfig: %w", err)
				}
				kubeConfig = c
			}
			cs, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				return nil, fmt.Errorf("building kubernetes clientset: %w", err)
			}
			clientset = cs
		}
		return &k8sStateStore{
			clientset: clientset,
			namespace: cfg.Kubernetes.Namespace,
			secret:    cfg.Kubernetes.Secret,
			name:      upstreamName,
		}, nil
	} else {
		dir := filepath.Join(cfg.StateDir, "tailscale-"+upstreamName)
		if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
			return nil, fmt.Errorf("creating %s: %w", dir, err)
		}
		st, err := store.NewFileStore(log.Printf, dir)
		if err != nil {
			return nil, fmt.Errorf("creating file store at %s: %w", dir, err)
		}
		return st, nil
	}
}
