package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminReturnPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		form     string
		fallback string
		want     string
	}{
		{name: "known page", form: "return=%2Fupstreams", fallback: "/", want: "/upstreams"},
		{name: "missing", form: "", fallback: "/settings", want: "/settings"},
		{name: "external URL rejected", form: "return=https%3A%2F%2Fexample.com", fallback: "/", want: "/"},
		{name: "unknown local path rejected", form: "return=%2Fadmin", fallback: "/dns-records", want: "/dns-records"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/action", nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.form != "" {
				req = httptest.NewRequest("POST", "/action", strings.NewReader(tc.form))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if got := adminReturnPath(req, tc.fallback); got != tc.want {
				t.Fatalf("adminReturnPath()=%q want %q", got, tc.want)
			}
		})
	}
}
