package signer

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LatticeBCLab/ak-auth-go/core"
	"github.com/stretchr/testify/assert"
)

func TestBuildAuthorization(t *testing.T) {
	s := New()
	got := s.BuildAuthorization("ak-001", "sig-123")
	want := "acs ak-001:sig-123"
	t.Logf("authorization=%s", got)
	assert.Equal(t, want, got, "authorization should match expected format")
}

func TestDefaultAlgorithmIsSHA256(t *testing.T) {
	s := New()
	t.Logf("default algorithm=%s", s.Algorithm().Name())
	assert.Equal(t, "HMAC-SHA256", s.Algorithm().Name(), "default signature algorithm should be SHA256")
}

func TestSignRequestAlgorithmSwitch(t *testing.T) {
	secret := []byte("demo-secret")
	headers := make(http.Header)
	headers.Set(core.AcceptHeader, "application/json")
	headers.Set(core.DateHeader, "Mon, 16 Mar 2026 10:30:00 GMT")

	query := url.Values{}
	query.Set("page", "1")

	in := core.CanonicalRequestInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Query:   query,
		Headers: headers,
	}

	sSHA256 := New()
	r256, err := sSHA256.SignRequest("ak-001", secret, in)
	assert.NoError(t, err, "sha256 sign should succeed")

	sSHA1 := New(WithSignatureAlgorithm(core.NewHMACSHA1()))
	r1, err := sSHA1.SignRequest("ak-001", secret, in)
	assert.NoError(t, err, "sha1 sign should succeed")

	sSHA512 := New(WithSignatureAlgorithm(core.NewHMACSHA512()))
	r512, err := sSHA512.SignRequest("ak-001", secret, in)
	assert.NoError(t, err, "sha512 sign should succeed")

	t.Logf("algorithms: sha256=%s sha1=%s sha512=%s", r256.Algorithm, r1.Algorithm, r512.Algorithm)
	t.Logf("signatures: sha256=%s sha1=%s sha512=%s", r256.Signature, r1.Signature, r512.Signature)

	assert.Equal(t, "HMAC-SHA256", r256.Algorithm)
	assert.Equal(t, "HMAC-SHA1", r1.Algorithm)
	assert.Equal(t, "HMAC-SHA512", r512.Algorithm)

	assert.NotEqual(t, r256.Signature, r1.Signature, "signatures should differ across algorithms")
	assert.NotEqual(t, r256.Signature, r512.Signature, "signatures should differ across algorithms")
	assert.NotEqual(t, r1.Signature, r512.Signature, "signatures should differ across algorithms")
}

func TestSignHelloEndpoint(t *testing.T) {
	secret := []byte("demo-secret")

	headers := make(http.Header)
	headers.Set(core.AcceptHeader, "application/json")
	headers.Set(core.DateHeader, time.Now().UTC().Format(time.RFC1123))

	in := core.CanonicalRequestInput{
		Method:  "GET",
		Path:    "/hello",
		Query:   url.Values{},
		Headers: headers,
	}

	s := New()
	signed, err := s.SignRequest("demo-ak", secret, in)
	assert.NoError(t, err, "sign hello endpoint should succeed")

	wantPrefix := "acs demo-ak:"
	assert.True(t, strings.HasPrefix(signed.Authorization, wantPrefix), "authorization should have expected prefix")
	assert.NotEmpty(t, signed.Signature, "signature should not be empty")

	wantAlg := "HMAC-SHA256"
	assert.Equal(t, wantAlg, signed.Algorithm, "algorithm should be default SHA256")

	dateStr := headers.Get(core.DateHeader)
	assert.NotEmpty(t, dateStr, "date header should not be empty")

	_, err = time.Parse(time.RFC1123, dateStr)
	assert.NoError(t, err, "date header should be RFC1123 format")
	assert.NotEmpty(t, signed.StringToSign, "string to sign should not be empty")

	t.Logf("Authorization: %s", signed.Authorization)
	t.Logf("Signature: %s", signed.Signature)
	t.Logf("Algorithm: %s", signed.Algorithm)
	t.Logf("StringToSign:\n%s", signed.StringToSign)

	expectedStringToSign := strings.Join([]string{
		"GET",
		"application/json",
		"",
		"",
		headers.Get(core.DateHeader),
	}, "\n") + "\n" + "" + "/hello"

	assert.Equal(t, expectedStringToSign, signed.StringToSign, "string to sign should match canonical expectation")
}

func TestSignHelloEndpointWithQuery(t *testing.T) {
	secret := []byte("demo-secret")

	headers := make(http.Header)
	headers.Set(core.AcceptHeader, "application/json")
	headers.Set(core.DateHeader, time.Now().UTC().Format(time.RFC1123))

	query := url.Values{}
	query.Set("page", "1")
	query.Set("size", "10")

	in := core.CanonicalRequestInput{
		Method:  "GET",
		Path:    "/hello",
		Query:   query,
		Headers: headers,
	}

	s := New()
	signed, err := s.SignRequest("demo-ak", secret, in)
	assert.NoError(t, err, "sign hello endpoint with query should succeed")

	assert.Contains(t, signed.StringToSign, "?page=1&size=10", "string to sign should contain query parameters")

	t.Logf("With Query StringToSign:\n%s", signed.StringToSign)
}
