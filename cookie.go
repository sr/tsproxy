package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lstoll/oidc/middleware"
)

const cookieName = "tsproxy-auth"

var _ middleware.SessionStore

type cookieAuthSession struct {
}

func (cookieAuthSession) Get(r *http.Request) (*middleware.SessionData, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return &middleware.SessionData{}, nil
		}
		return nil, fmt.Errorf("fetching cookie %s: %w", cookieName, err)
	}

	var sd middleware.SessionData

	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, fmt.Errorf("base64 decode cookie: %w", err)
	}
	rdr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	if err := json.NewDecoder(rdr).Decode(&sd); err != nil {
		return nil, fmt.Errorf("decoding cookie: %w", err)
	}

	return &sd, nil
}

// Save should store the updated session. If the session data is nil, the
// session should be deleted.
func (cookieAuthSession) Save(w http.ResponseWriter, r *http.Request, sd *middleware.SessionData) error {
	if sd == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			MaxAge:   -1,
			Value:    "",
		})
		return nil
	}

	// unset access token as we don't use it, and refresh token because it's not
	// safe to store unencrypted.
	if sd.Token != nil {
		sd.Token.AccessToken = ""
		sd.Token.RefreshToken = ""
	}

	buf := bytes.Buffer{}
	gzw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gzw).Encode(sd); err != nil {
		return fmt.Errorf("zip/enc cookie: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return fmt.Errorf("closing gzip writer: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Value:    base64.RawURLEncoding.EncodeToString(buf.Bytes()),
	})

	return nil
}
