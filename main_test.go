package main

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseUpstream(t *testing.T) {
	for _, tc := range []struct {
		upstream string
		want     upstream
		err      error
	}{
		{
			upstream: "test=http://example.com:-80/",
			want:     upstream{},
			err:      errors.New(`parse "http://`),
		},
		{
			upstream: "test=http://localhost",
			want:     upstream{name: "test", backend: mustParseURL("http://localhost")},
		},
		{
			upstream: "test=http://localhost;prometheus",
			want:     upstream{name: "test", backend: mustParseURL("http://localhost"), prometheus: true},
		},
		{
			upstream: "test=http://localhost;foo",
			want:     upstream{},
			err:      errors.New("unsupported option: foo"),
		},
	} {
		tc := tc
		t.Run(tc.upstream, func(t *testing.T) {
			t.Parallel()
			up, err := parseUpstreamFlag(tc.upstream)
			if tc.err != nil {
				if err == nil {
					t.Fatalf("want err %v, got nil", tc.err)
				}
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Fatalf("want err %v, got %v", tc.err, err)
				}
			}
			if tc.err == nil && err != nil {
				t.Fatalf("want no err, got %v", err)
			}
			if diff := cmp.Diff(tc.want, up, cmp.Exporter(func(_ reflect.Type) bool { return true })); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func mustParseURL(s string) *url.URL {
	v, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}
