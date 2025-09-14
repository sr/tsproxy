package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/oauth2ext/oidcmiddleware"
	"tailscale.com/ipn/ipnstate"
)

type groupClaims struct {
	Groups []string `json:"groups"`
}

func buildMiddlewareForUpstream(ctx context.Context, st *ipnstate.Status, upstream upstream) (func(http.Handler) http.Handler, error) {
	baseURL := "https://" + strings.TrimSuffix(st.Self.DNSName, ".")

	p, err := oidc.DiscoverProvider(ctx, upstream.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover: %w", err)
	}

	oidcOAuth2ConfigFn, err := oidcOAuth2ConfigFn(ctx, upstream, baseURL+"/.tsproxy/oidc-callback")
	if err != nil {
		return nil, fmt.Errorf("oidc: oauth2 config: %w", err)
	}

	gmw := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(upstream.OIDCRequireGroups) == 0 {
				h.ServeHTTP(w, r)
				return
			}

			cl, ok := oidcmiddleware.IDClaimsFromContext(r.Context())
			if !ok {
				slog.Error("oidc: missing id claims")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			var gc groupClaims
			if err := cl.UnmarshalClaims(&gc); err != nil {
				slog.Error("oidc: unmarshalling group claims", "error", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			allowed := false
			for _, required := range upstream.OIDCRequireGroups {
				if slices.Contains(gc.Groups, required) {
					allowed = true
					break
				}
			}
			if allowed {
				h.ServeHTTP(w, r)
				return
			}

			slog.WarnContext(r.Context(), "oidc: user not in required groups", "upstream", upstream.Name, "groups", gc.Groups)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		})
	}

	omw := &oidcmiddleware.Handler{
		Provider:           p,
		OAuth2ConfigSource: oidcOAuth2ConfigFn,
		SessionStore:       &oidcmiddleware.Cookiestore{},
	}

	return func(h http.Handler) http.Handler {
		return omw.Wrap(gmw(h))
	}, nil
}

func oidcOAuth2ConfigFn(ctx context.Context, upstream upstream, redirURL string) (func(context.Context) (oauth2.Config, error), error) {
	p, err := oidc.DiscoverProvider(ctx, upstream.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover: %w", err)
	}

	scopes := []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}
	if len(upstream.OIDCRequireGroups) > 0 {
		scopes = append(scopes, "groups")
	}

	o2cfg := &oauth2.Config{
		Endpoint:    p.Endpoint(),
		Scopes:      scopes,
		RedirectURL: redirURL,
	}

	if !upstream.OIDCRegisterClient {
		// just return something that uses the current config.
		return func(ctx context.Context) (oauth2.Config, error) {
			c := *o2cfg
			c.ClientID = upstream.OIDCClientID
			c.ClientSecret = upstream.OIDCClientSecret
			return c, nil
		}, nil
	}

	// otherwise register a client, and run a routine to update the config.
	regResp, err := registerOIDCClient(ctx, upstream, p, []string{redirURL})
	if err != nil {
		return nil, fmt.Errorf("oidc: register client: %w", err)
	}

	o2cfg.ClientID = regResp.ClientID
	o2cfg.ClientSecret = regResp.ClientSecret

	slog.Info("oidc: registered client", "upstream", upstream.Name, "client_id", o2cfg.ClientID)

	reRegisterDelay := time.Hour // for now, to exercise it.
	// if regResp.ClientSecretExpiresAt != nil {
	// 	ttl := time.Duration(*regResp.ClientSecretExpiresAt-time.Now().Unix()) * time.Second
	// 	reRegisterDelay = time.Duration(float64(ttl) * 0.75)
	// } else {
	// 	reRegisterDelay = time.Hour // TODO set a better default
	// }

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(reRegisterDelay):
				newRegResp, err := registerOIDCClient(ctx, upstream, p, []string{redirURL})
				if err != nil {
					slog.Error("oidc: failed to register client", "upstream", upstream.Name, "error", err)
					// If registration fails, try again sooner
					reRegisterDelay = time.Minute
					continue
				}
				slog.Info("oidc: registered client", "upstream", upstream.Name, "client_id", o2cfg.ClientID)
				o2cfg.ClientID = newRegResp.ClientID
				o2cfg.ClientSecret = newRegResp.ClientSecret
				// On success, wait longer before next registration
				// TODO - same calculation as above
				reRegisterDelay = time.Hour
			}
		}
	}()

	return func(ctx context.Context) (oauth2.Config, error) {
		return *o2cfg, nil
	}, nil
}

// registerOIDCClient performs dynamic client registration with the OIDC provider
func registerOIDCClient(ctx context.Context, upstream upstream, provider *oidc.Provider, redirectURIs []string) (*oidcclientreg.ClientRegistrationResponse, error) {
	// Create registration request
	request := &oidcclientreg.ClientRegistrationRequest{
		ClientName:      fmt.Sprintf("tsproxy-%s", upstream.Name),
		RedirectURIs:    redirectURIs,
		ApplicationType: "web",
		ResponseTypes:   []string{"code"},
		GrantTypes:      []string{"authorization_code"},
	}

	if slices.Contains(provider.Metadata.IDTokenSigningAlgValuesSupported, "ES256") {
		request.IDTokenSignedResponseAlg = "ES256"
	}

	response, err := oidcclientreg.RegisterWithProvider(ctx, provider, request)
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}

	return response, nil
}
