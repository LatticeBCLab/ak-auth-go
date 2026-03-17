package signer

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/LatticeBCLab/ak-auth-go/core"
)

func TestBuildAuthorization(t *testing.T) {
	s := New()
	got := s.BuildAuthorization("ak-001", "sig-123")
	want := "acs ak-001:sig-123"
	if got != want {
		t.Fatalf("unexpected authorization\nwant: %s\ngot:  %s", want, got)
	}
}

func TestDefaultAlgorithmIsSHA256(t *testing.T) {
	s := New()
	if s.Algorithm().Name() != "HMAC-SHA256" {
		t.Fatalf("unexpected default algorithm: %s", s.Algorithm().Name())
	}
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
	if err != nil {
		t.Fatalf("sha256 sign failed: %v", err)
	}

	sSHA1 := New(WithSignatureAlgorithm(core.NewHMACSHA1()))
	r1, err := sSHA1.SignRequest("ak-001", secret, in)
	if err != nil {
		t.Fatalf("sha1 sign failed: %v", err)
	}

	sSHA512 := New(WithSignatureAlgorithm(core.NewHMACSHA512()))
	r512, err := sSHA512.SignRequest("ak-001", secret, in)
	if err != nil {
		t.Fatalf("sha512 sign failed: %v", err)
	}

	if r256.Algorithm != "HMAC-SHA256" || r1.Algorithm != "HMAC-SHA1" || r512.Algorithm != "HMAC-SHA512" {
		t.Fatalf("unexpected algorithms: %s / %s / %s", r256.Algorithm, r1.Algorithm, r512.Algorithm)
	}

	if r256.Signature == r1.Signature || r256.Signature == r512.Signature || r1.Signature == r512.Signature {
		t.Fatalf("signatures should differ across algorithms")
	}
}
