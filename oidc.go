package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"lds.li/oauth2ext/claims"
	"lds.li/oauth2ext/middleware"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/oauth2ext/provider"
	"tailscale.com/ipn/ipnstate"
)

const middlewareRefreshInterval = 24 * time.Hour

func buildMiddlewareForUpstream(ctx context.Context, st *ipnstate.Status, upstream upstream) (func(http.Handler) http.Handler, error) {
	redirectURL := "https://" + strings.TrimSuffix(st.Self.DNSName, ".") + "/.tsproxy/oidc-callback"

	var (
		lastRefreshed time.Time
		currentMw     func(http.Handler) http.Handler
		refreshMu     sync.RWMutex
	)

	gmw := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(upstream.OIDCRequireGroups) == 0 {
				h.ServeHTTP(w, r)
				return
			}

			cl, ok := claimsFromContext(r.Context())
			if !ok {
				slog.Error("oidc: missing id claims")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			groups, err := cl.ArrayClaim("groups")
			if err != nil {
				slog.Error("oidc: getting groups claim", "error", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if groups == nil {
				slog.Error("oidc: missing groups claim")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			strGroups := []string{}
			for _, group := range groups {
				strGroups = append(strGroups, group.(string))
			}

			allowed := false
			for _, required := range upstream.OIDCRequireGroups {
				if slices.Contains(strGroups, required) {
					allowed = true
					break
				}
			}
			if allowed {
				h.ServeHTTP(w, r)
				return
			}

			slog.WarnContext(r.Context(), "oidc: user not in required groups", "upstream", upstream.Name, "groups", strGroups)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		})
	}

	refreshMw := func() error {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		if time.Since(lastRefreshed) < middlewareRefreshInterval {
			return nil
		}
		clientID, clientSecret, err := oidcClientCredentials(ctx, upstream, redirectURL)
		if err != nil {
			return err
		}
		omw, err := middleware.NewIDSSOHandlerFromDiscovery(ctx, nil, upstream.OIDCIssuer, clientID, clientSecret, redirectURL)
		if err != nil {
			return fmt.Errorf("oidc: from discovery: %w", err)
		}
		if len(upstream.OIDCRequireGroups) > 0 {
			omw.OAuth2Config.Scopes = append(omw.OAuth2Config.Scopes, "groups")
		}

		lastRefreshed = time.Now()
		currentMw = func(h http.Handler) http.Handler {
			return omw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cl, ok := omw.IDClaimsFromContext(r.Context())
				if !ok {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				r = r.WithContext(contextWithClaims(r.Context(), cl))
				gmw(h).ServeHTTP(w, r)
			}))
		}

		return nil
	}

	// Prime middleware so we never serve with nil currentMw.
	if err := refreshMw(); err != nil {
		return nil, fmt.Errorf("oidc: initial middleware refresh: %w", err)
	}

	// Refresh middleware periodically (provider discovery, registration if used, then new handler).
	go func() {
		ticker := time.NewTicker(middlewareRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := refreshMw(); err != nil {
					slog.Error("oidc: background middleware refresh failed", "upstream", upstream.Name, "error", err)
				}
			}
		}
	}()

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			refreshMu.RLock()
			mw := currentMw
			refreshMu.RUnlock()
			if mw == nil {
				// Fallback: e.g. initial refresh failed after we started serving.
				if err := refreshMw(); err != nil {
					slog.Error("oidc: failed to refresh middleware", "error", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				refreshMu.RLock()
				mw = currentMw
				refreshMu.RUnlock()
				if mw == nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			}
			mw(h).ServeHTTP(w, r)
		})
	}, nil
}

// oidcClientCredentials returns client ID and secret for the upstream (static config or dynamic registration).
func oidcClientCredentials(ctx context.Context, upstream upstream, redirectURL string) (clientID, clientSecret string, err error) {
	if !upstream.OIDCRegisterClient {
		return upstream.OIDCClientID, upstream.OIDCClientSecret, nil
	}
	p, err := provider.DiscoverOIDCProvider(ctx, upstream.OIDCIssuer)
	if err != nil {
		return "", "", fmt.Errorf("oidc: discover: %w", err)
	}
	regResp, err := registerOIDCClient(ctx, upstream, p, []string{redirectURL})
	if err != nil {
		return "", "", fmt.Errorf("oidc: register client: %w", err)
	}
	slog.Info("oidc: registered client", "upstream", upstream.Name, "client_id", regResp.ClientID)
	return regResp.ClientID, regResp.ClientSecret, nil
}

// registerOIDCClient performs dynamic client registration with the OIDC provider
func registerOIDCClient(ctx context.Context, upstream upstream, prov *provider.Provider, redirectURIs []string) (*oidcclientreg.ClientRegistrationResponse, error) {
	// Create registration request
	request := &oidcclientreg.ClientRegistrationRequest{
		ClientName:      fmt.Sprintf("tsproxy-%s", upstream.Name),
		RedirectURIs:    redirectURIs,
		ApplicationType: "web",
		ResponseTypes:   []string{"code"},
		GrantTypes:      []string{"authorization_code"},
	}

	oidcMetadata, ok := prov.Metadata.(*provider.OIDCProviderMetadata)
	if !ok {
		return nil, fmt.Errorf("provider metadata is not an OIDC provider metadata")
	}

	if slices.Contains(oidcMetadata.IDTokenSigningAlgValuesSupported, "ES256") {
		request.IDTokenSignedResponseAlg = "ES256"
	}

	response, err := oidcclientreg.RegisterWithProvider(ctx, prov, request)
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}

	return response, nil
}

type claimsKey struct{}

func contextWithClaims(ctx context.Context, cl *claims.VerifiedID) context.Context {
	return context.WithValue(ctx, claimsKey{}, cl)
}

func claimsFromContext(ctx context.Context) (*claims.VerifiedID, bool) {
	cl, ok := ctx.Value(claimsKey{}).(*claims.VerifiedID)
	if !ok {
		return nil, false
	}
	return cl, true
}
