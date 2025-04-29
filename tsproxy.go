package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"strings"
	"syscall"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/middleware"
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
	Funnel     *funnelConfig
}

type funnelConfig struct {
	Insecure     bool
	Issuer       string
	ClientID     string
	ClientSecret string
	User         string
	Password     string
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
		// TODO(sr) Instrument proxy.Transport
		proxy := &httputil.ReverseProxy{
			Rewrite: func(req *httputil.ProxyRequest) {
				req.SetURL(backendURL)
				req.SetXForwarded()
				req.Out.Host = req.In.Host
			},
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			log.Error("upstream error", lerr(err))
		}

		instrument := func(h http.Handler) http.Handler {
			return promhttp.InstrumentHandlerInFlight(
				requestsInFlight.With(prometheus.Labels{"upstream": upstream.Name}),
				promhttp.InstrumentHandlerDuration(
					duration.MustCurryWith(prometheus.Labels{"upstream": upstream.Name}),
					promhttp.InstrumentHandlerCounter(
						requests.MustCurryWith(prometheus.Labels{"upstream": upstream.Name}),
						h,
					),
				),
			)
		}

		{
			var srv *http.Server
			g.Add(func() error {
				st, err := ts.Up(ctx)
				if err != nil {
					return fmt.Errorf("tailscale: wait for tsnet %s to be ready: %w", upstream.Name, err)
				}

				srv = &http.Server{Handler: instrument(redirect(st.Self.DNSName, false, tailnet(log, lc, proxy)))}
				ln, err := ts.Listen("tcp", ":80")
				if err != nil {
					return fmt.Errorf("tailscale: listen for %s on port 80: %w", upstream.Name, err)
				}

				// register in service discovery when we're ready.
				targets[i] = target{name: upstream.Name, prometheus: upstream.Prometheus, magicDNS: st.Self.DNSName}

				return srv.Serve(ln)
			}, func(_ error) {
				if srv != nil {
					if err := srv.Close(); err != nil {
						log.Error("server shutdown", lerr(err))
					}
				}
				cancel()
			})
		}
		{
			var srv *http.Server
			g.Add(func() error {
				st, err := ts.Up(ctx)
				if err != nil {
					return fmt.Errorf("tailscale: wait for tsnet %s to be ready: %w", upstream.Name, err)
				}

				srv = &http.Server{
					TLSConfig: &tls.Config{GetCertificate: lc.GetCertificate},
					Handler:   instrument(redirect(st.Self.DNSName, true, tailnet(log, lc, proxy))),
				}

				ln, err := ts.Listen("tcp", ":443")
				if err != nil {
					return fmt.Errorf("tailscale: listen for %s on port 443: %w", upstream.Name, err)
				}
				return srv.ServeTLS(ln, "", "")
			}, func(_ error) {
				if srv != nil {
					if err := srv.Close(); err != nil {
						log.Error("server shutdown", lerr(err))
					}
				}
				cancel()
			})
		}
		if funnel := upstream.Funnel; funnel != nil {
			{
				var srv *http.Server
				g.Add(func() error {
					st, err := ts.Up(ctx)
					if err != nil {
						return fmt.Errorf("tailscale: wait for tsnet %s to be ready: %w", upstream.Name, err)
					}

					var handler http.Handler
					switch {
					case funnel.Insecure:
						handler = insecureFunnel(log, lc, proxy)
					case funnel.Issuer != "":
						redir := &url.URL{Scheme: "https", Host: strings.TrimSuffix(st.Self.DNSName, "."), Path: ".oidc-callback"}
						wrapper, err := middleware.NewFromDiscovery(ctx, nil, funnel.Issuer, funnel.ClientID, funnel.ClientSecret, redir.String())
						if err != nil {
							return fmt.Errorf("oidc middleware for %s: %w", upstream.Name, err)
						}
						wrapper.OAuth2Config.Scopes = append(wrapper.OAuth2Config.Scopes, oidc.ScopeProfile)

						handler = wrapper.Wrap(oidcFunnel(log, lc, proxy))
					case funnel.User != "":
						if _, fn, ok := strings.Cut(funnel.Password, "file://"); ok {
							data, err := os.ReadFile(fn)
							if err != nil {
								return fmt.Errorf("upstream %s: read password file %s: %w", upstream.Name, fn, err)
							}
							funnel.Password = strings.TrimSpace(string(data))
						}
						handler = insecureFunnel(log, lc, basicAuth(log, funnel.User, funnel.Password, proxy))
					default:
						return fmt.Errorf("upstream %s: must set funnel.insecure or funnel.issuer", upstream.Name)
					}
					srv = &http.Server{Handler: instrument(redirect(st.Self.DNSName, true, handler))}

					ln, err := ts.ListenFunnel("tcp", ":443", tsnet.FunnelOnly())
					if err != nil {
						return fmt.Errorf("tailscale: funnel for %s on port 443: %w", upstream.Name, err)
					}
					return srv.Serve(ln)
				}, func(_ error) {
					if srv != nil {
						if err := srv.Close(); err != nil {
							log.Error("server shutdown", lerr(err))
						}
					}
					cancel()
				})
			}
		}
	}

	return g.Run()
}

func redirect(fqdn string, forceSSL bool, next http.Handler) http.Handler {
	if fqdn == "" {
		panic("redirect: fqdn cannot be empty")
	}
	fqdn = strings.TrimSuffix(fqdn, ".")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if forceSSL && r.TLS == nil {
			http.Redirect(w, r, fmt.Sprintf("https://%s%s", fqdn, r.RequestURI), http.StatusPermanentRedirect)
			return
		}

		if r.TLS != nil && strings.TrimSuffix(r.Host, ".") != fqdn {
			http.Redirect(w, r, fmt.Sprintf("https://%s%s", fqdn, r.RequestURI), http.StatusPermanentRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func basicAuth(logger *slog.Logger, user, password string, next http.Handler) http.Handler {
	if user == "" || password == "" {
		panic("user and password are required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok {
			userCheck := subtle.ConstantTimeCompare([]byte(user), []byte(u))
			passwordCheck := subtle.ConstantTimeCompare([]byte(password), []byte(p))
			if userCheck == 1 && passwordCheck == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		logger.ErrorContext(r.Context(), "authentication failed", slog.String("user", u))
		w.Header().Set("WWW-Authenticate", "Basic realm=\"protected\", charset=\"UTF-8\"")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	})
}

func tailnet(logger *slog.Logger, lc tailscaleLocalClient, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		whois, err := tsWhoIs(lc, r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.ErrorContext(r.Context(), "tailscale whois", lerr(err))
			return
		}

		// Proxy requests from tagged nodes as is.
		if whois.Node.IsTagged() {
			next.ServeHTTP(w, r)
			return
		}

		req := r.Clone(r.Context())
		req.Header.Set("X-Webauth-User", whois.UserProfile.LoginName)
		req.Header.Set("X-Webauth-Name", whois.UserProfile.DisplayName)
		next.ServeHTTP(w, req)
	})
}

func insecureFunnel(logger *slog.Logger, lc tailscaleLocalClient, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		whois, err := tsWhoIs(lc, r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.ErrorContext(r.Context(), "tailscale whois", lerr(err))
			return
		}
		if !whois.Node.IsTagged() {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.ErrorContext(r.Context(), "funnel handler got request from non-tagged node")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func oidcFunnel(logger *slog.Logger, lc tailscaleLocalClient, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		whois, err := tsWhoIs(lc, r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.ErrorContext(r.Context(), "tailscale whois", lerr(err))
			return
		}
		if !whois.Node.IsTagged() {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.ErrorContext(r.Context(), "funnel handler got request from non-tagged node")
			return
		}

		tok := middleware.IDJWTFromContext(r.Context())
		if tok == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.ErrorContext(r.Context(), "jwt token missing")
			return
		}
		email, err := tok.StringClaim("email")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.ErrorContext(r.Context(), "claim missing", slog.String("claim", "email"))
			return
		}
		name, err := tok.StringClaim("name")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.ErrorContext(r.Context(), "claim missing", slog.String("claim", "name"))
			return
		}

		req := r.Clone(r.Context())
		req.Header.Set("X-Webauth-User", email)
		req.Header.Set("X-Webauth-Name", name)

		next.ServeHTTP(w, req)
	})
}

type tailscaleLocalClient interface {
	WhoIs(context.Context, string) (*apitype.WhoIsResponse, error)
}

func tsWhoIs(lc tailscaleLocalClient, r *http.Request) (*apitype.WhoIsResponse, error) {
	whois, err := lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("tailscale whois: %w", err)
	}

	if whois.Node == nil {
		return nil, errors.New("tailscale whois: node missing")
	}

	if whois.UserProfile == nil {
		return nil, errors.New("tailscale whois: user profile missing")
	}
	return whois, nil
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
	return slog.Any("err", err)
}
