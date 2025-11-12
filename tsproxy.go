package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/middleware"
	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/tailscale/hujson"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
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
	var defaultStatedir string
	if dir, err := os.UserCacheDir(); err == nil {
		defaultStatedir = filepath.Join(dir, "tsproxy")
	}

	var (
		upsfile     = flag.String("upstream", "", "path to JSON file containing the list of upstream(s) and their settings")
		statedir    = flag.String("statedir", defaultStatedir, "path to the top-level state directory")
		state       = flag.String("state", "", "leave empty to store state files in --statedir; use \"incus:socket\" to persist them as objects in an incus bucket")
		addr        = flag.String("http", "", "optional [ip]:port for serving metrics and service discovery; use tailscale:port to listen on the node's tailscale IPs")
		incusBucket = flag.String("incus-bucket", "", "incus bucket in the format storage-pool:bucket-name; required for --state=incus:socket")
		ver         = flag.Bool("version", false, "print version information and exit")
	)
	flag.Parse()

	if *ver {
		fmt.Fprintln(os.Stdout, version.Print("tsproxy"))
		os.Exit(0)
	}

	if *upsfile == "" {
		return fmt.Errorf("required flag missing: --upstream")
	}
	in, err := os.ReadFile(*upsfile)
	if err != nil {
		return err
	}
	inJSON, err := hujson.Standardize(in)
	if err != nil {
		return fmt.Errorf("decode --upstream file: %w", err)
	}
	var upstreams []upstream
	if err := json.Unmarshal(inJSON, &upstreams); err != nil {
		return fmt.Errorf("decode --upstream file: %w", err)
	}

	if *statedir == "" {
		return fmt.Errorf("required flag missing: --statedir")
	}
	if err := os.MkdirAll(*statedir, 0o700); err != nil {
		return err
	}

	var (
		minioClient *minio.Client
		bucketName  string
	)
	switch *state {
	case "incus:socket":
		if *incusBucket == "" {
			return errors.New("--incus-bucket is required for --state=incus")
		}
		pool, bucket, ok := strings.Cut(*incusBucket, ":")
		if !ok {
			return errors.New("--incus-bucket is invalid; use storage-pool:bucket-name format")
		}
		bucketName = bucket

		cli, err := incus.ConnectIncusUnixWithContext(ctx, "", nil)
		if err != nil {
			return fmt.Errorf("incus: connect to unix socket: %w", err)
		}

		serv, _, err := cli.GetServer()
		if err != nil {
			return err
		}
		addr, ok := serv.Config["core.storage_buckets_address"]
		if !ok {
			return errors.New("incus: server config option not set: core.storage_buckets_address")
		}

		keys, err := cli.GetStoragePoolBucketKeys(pool, bucket)
		if err != nil {
			return fmt.Errorf("incus: get access keys for bucket %s: %w", bucket, err)
		}
		var adminKey api.StorageBucketKey
		for _, k := range keys {
			if k.Role == "admin" {
				adminKey = k
				break
			}
		}
		if adminKey.Name == "" {
			return fmt.Errorf("incus: no admin key found for bucket %s", bucket)
		}
		minioClient, err = minio.New(addr, &minio.Options{
			Creds:  credentials.NewStaticV4(adminKey.AccessKey, adminKey.SecretKey, ""),
			Secure: true,
		})
		if err != nil {
			return fmt.Errorf("incus: connect to storage bucket endpoint %s: %w", addr, err)
		}
	case "":
		// noop but valid
	default:
		return fmt.Errorf("--state=%s is not supported", *state)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))
	slog.SetDefault(logger)

	// service discovery targets (self + all upstreams)
	targets := make([]target, len(upstreams)+1)

	var g run.Group
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.Add(run.SignalHandler(ctx, os.Interrupt, syscall.SIGTERM))

	if *addr != "" {
		host, port, err := net.SplitHostPort(*addr)
		if err != nil {
			return fmt.Errorf("parse --http flag: %w", err)
		}

		prometheus.MustRegister(versioncollector.NewCollector("tsproxy"))

		http.Handle("/metrics", promhttp.Handler())
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

		var listeners []net.Listener
		if host == "tailscale" {
			st, err := (&local.Client{}).Status(ctx)
			if err != nil {
				return fmt.Errorf("tailscale: get node status: %w", err)
			}
			if v := len(st.Self.TailscaleIPs); v != 2 {
				return fmt.Errorf("want 2 tailscale IPs, got %d", v)
			}
			for _, ip := range st.Self.TailscaleIPs {
				ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), port))
				if err != nil {
					return fmt.Errorf("listen on %s:%s: %w", ip, port, err)
				}
				listeners = append(listeners, ln)
			}

			http.Handle("/sd", serveDiscovery(net.JoinHostPort(st.Self.DNSName, port), targets))
		} else {
			http.Handle("/sd", serveDiscovery(*addr, targets))

			ln, err := net.Listen("tcp", *addr)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", *addr, err)
			}
			listeners = append(listeners, ln)
		}

		srv := &http.Server{}
		for _, ln := range listeners {
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
			RunWebClient: true,
			UserLogf: func(format string, args ...any) {
				log.Info("tailscale", slog.String("msg", fmt.Sprintf(format, args...)))
			},
			Dir: filepath.Join(*statedir, "tailscale-"+upstream.Name),
		}
		if *state == "incus:socket" {
			st, err := newIncusStore(minioClient, bucketName, upstream)
			if err != nil {
				return fmt.Errorf("initialize incus state store for upstream %s: %w", upstream.Name, err)
			}
			ts.Store = st
		}
		defer ts.Close()

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

type incusStore struct {
	cache  mem.Store
	client *minio.Client
	bucket string
	object string
}

func newIncusStore(client *minio.Client, bucket string, up upstream) (ipn.StateStore, error) {
	store := &incusStore{
		client: client,
		bucket: bucket,
		object: "tailscale-" + up.Name,
	}

	obj, err := client.GetObject(context.TODO(), store.bucket, store.object, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("incus: get object %s in %s: %w", store.object, store.bucket, err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		resp := minio.ToErrorResponse(err)
		if resp.StatusCode == http.StatusNotFound {
			data = []byte("{}")
		} else {
			return nil, fmt.Errorf("incus: read object %s in %s: %w", store.object, store.bucket, err)
		}
	}

	if err := store.cache.LoadFromJSON(data); err != nil {
		return nil, fmt.Errorf("incus: load state in memory: %w", err)
	}

	return store, nil
}

// ReadState implements the ipn.Store interface.
func (s *incusStore) ReadState(id ipn.StateKey) ([]byte, error) {
	return s.cache.ReadState(id)
}

// WriteState implements the ipn.Store interface.
func (s *incusStore) WriteState(id ipn.StateKey, bs []byte) error {
	if err := s.cache.WriteState(id, bs); err != nil {
		return err
	}
	data, err := s.cache.ExportToJSON()
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(context.TODO(), s.bucket, s.object, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		return fmt.Errorf("incus: put object %s in bucket %s: %w", s.object, s.bucket, err)
	}
	return nil
}
