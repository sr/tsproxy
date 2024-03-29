package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/middleware"
	"golang.org/x/oauth2"
)

func TestCookieStore(t *testing.T) {
	st := &cookieAuthSession{}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	sessData := &middleware.SessionData{
		State: "aaaaa",
		Token: &oidc.MarshaledToken{
			Token: (&oauth2.Token{
				AccessToken:  "access",
				RefreshToken: "refresh",
			}).WithExtra(map[string]any{
				"id_token": "idtoken",
			}),
		},
	}

	if err := st.Save(w, r, sessData); err != nil {
		t.Fatal(err)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}

	got, err := st.Get(r)
	if err != nil {
		t.Fatal(err)
	}

	if got == nil {
		t.Fatal("got nil response")
	}

	if got.State != "aaaaa" {
		t.Error("state missing")
	}

	if got.Token.RefreshToken != "" {
		t.Error("should be no refresh token")
	}

	if idt, ok := got.Token.Extra("id_token").(string); !ok || idt != "idtoken" {
		t.Errorf("response has no id token, ok: %t val: %s", ok, idt)
	}
}
