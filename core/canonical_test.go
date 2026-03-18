package core

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildCanonicalizedResource(t *testing.T) {
	q := url.Values{}
	q.Add("b", "2")
	q.Add("a", "hello world")
	q.Add("a", "1")

	got := BuildCanonicalizedResource("/api/v1/items", q)
	want := "/api/v1/items?a=1&a=hello%20world&b=2"
	t.Logf("canonicalized resource=%s", got)
	assert.Equal(t, want, got, "canonicalized resource should be sorted and encoded")
}

func TestBuildCanonicalizedHeaders(t *testing.T) {
	headers := make(http.Header)
	headers.Add("X-Acs-Trace-Id", " req-001 ")
	headers.Add("x-acs-signature-nonce", " nonce-1 ")
	headers.Add("Content-Type", "application/json")

	got := BuildCanonicalizedHeaders(headers)
	t.Logf("canonicalized headers:\n%s", got)
	assert.Contains(t, got, "x-acs-signature-nonce:nonce-1\n", "nonce header should be included")
	assert.Contains(t, got, "x-acs-trace-id:req-001\n", "trace header should be included")
	assert.NotContains(t, strings.ToLower(got), "content-type", "non x-acs header should not be included")
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
	t.Logf("string to sign:\n%s", got)

	assert.True(t, strings.HasPrefix(got, "GET\napplication/json\n\n\nMon, 16 Mar 2026 10:30:00 GMT\n"), "stringToSign should have expected prefix")
	assert.Contains(t, got, "/v1/demo?size=10", "stringToSign should include canonicalized resource")
}
