package core

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBuildCanonicalizedResource(t *testing.T) {
	q := url.Values{}
	q.Add("b", "2")
	q.Add("a", "hello world")
	q.Add("a", "1")

	got := BuildCanonicalizedResource("/api/v1/items", q)
	want := "/api/v1/items?a=1&a=hello%20world&b=2"
	if got != want {
		t.Fatalf("canonicalized resource mismatch\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildCanonicalizedHeaders(t *testing.T) {
	headers := make(http.Header)
	headers.Add("X-Acs-Trace-Id", " req-001 ")
	headers.Add("x-acs-signature-nonce", " nonce-1 ")
	headers.Add("Content-Type", "application/json")

	got := BuildCanonicalizedHeaders(headers)
	if !strings.Contains(got, "x-acs-signature-nonce:nonce-1\n") {
		t.Fatalf("missing nonce header in canonicalized headers: %q", got)
	}
	if !strings.Contains(got, "x-acs-trace-id:req-001\n") {
		t.Fatalf("missing trace header in canonicalized headers: %q", got)
	}
	if strings.Contains(strings.ToLower(got), "content-type") {
		t.Fatalf("non x-acs header should not be included: %q", got)
	}
}

func TestBuildStringToSign(t *testing.T) {
	headers := make(http.Header)
	headers.Set(AcceptHeader, "application/json")
	headers.Set(DateHeader, "Mon, 16 Mar 2026 10:30:00 GMT")

	q := url.Values{}
	q.Set("size", "10")

	got := BuildStringToSign(CanonicalRequestInput{
		Method:  "get",
		Path:    "/v1/demo",
		Query:   q,
		Headers: headers,
	})

	if !strings.HasPrefix(got, "GET\napplication/json\n\n\nMon, 16 Mar 2026 10:30:00 GMT\n") {
		t.Fatalf("unexpected stringToSign prefix: %q", got)
	}
	if !strings.Contains(got, "/v1/demo?size=10") {
		t.Fatalf("unexpected canonicalized resource in stringToSign: %q", got)
	}
}
