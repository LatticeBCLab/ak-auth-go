package verifier

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/LatticeBCLab/ak-auth-go/core"
	"github.com/LatticeBCLab/ak-auth-go/signer"
)

type staticSecretProvider struct {
	secret  []byte
	enabled bool
	err     error
}

func (p *staticSecretProvider) GetSecret(ctx context.Context, accessKeyID string) ([]byte, bool, error) {
	if p.err != nil {
		return nil, false, p.err
	}
	return p.secret, p.enabled, nil
}

type memoryNonceStore struct {
	seen map[string]struct{}
}

func (m *memoryNonceStore) UseNonce(ctx context.Context, accessKeyID, nonce string, ttl time.Duration) (bool, error) {
	if m.seen == nil {
		m.seen = make(map[string]struct{})
	}
	key := accessKeyID + ":" + nonce
	if _, ok := m.seen[key]; ok {
		return false, nil
	}
	m.seen[key] = struct{}{}
	return true, nil
}

func TestVerifySuccessSHA256(t *testing.T) {
	secret := []byte("demo-secret")
	provider := &staticSecretProvider{secret: secret, enabled: true}

	now := time.Date(2026, 3, 16, 10, 30, 0, 0, time.UTC)
	headers := make(http.Header)
	headers.Set(core.AcceptHeader, "application/json")
	headers.Set(core.DateHeader, now.Format(time.RFC1123))

	q := url.Values{}
	q.Set("page", "1")

	s := signer.New()
	signed, err := s.SignRequest("ak-001", secret, core.CanonicalRequestInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Query:   q,
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("sign request failed: %v", err)
	}
	headers.Set(core.AuthorizationHeader, signed.Authorization)

	v := New(provider, withNowFn(func() time.Time { return now }))
	res, err := v.Verify(context.Background(), VerifyInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Query:   q,
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if res.AccessKeyID != "ak-001" {
		t.Fatalf("unexpected access key id: %s", res.AccessKeyID)
	}
	if res.Algorithm != "HMAC-SHA256" {
		t.Fatalf("unexpected algorithm: %s", res.Algorithm)
	}
}

func TestVerifySuccessSHA1AndMismatchOnDifferentAlgorithm(t *testing.T) {
	secret := []byte("demo-secret")
	provider := &staticSecretProvider{secret: secret, enabled: true}

	now := time.Date(2026, 3, 16, 10, 30, 0, 0, time.UTC)
	headers := make(http.Header)
	headers.Set(core.AcceptHeader, "application/json")
	headers.Set(core.DateHeader, now.Format(time.RFC1123))

	s := signer.New(signer.WithSignatureAlgorithm(core.NewHMACSHA1()))
	signed, err := s.SignRequest("ak-001", secret, core.CanonicalRequestInput{
		Method:  "POST",
		Path:    "/api/v1/items",
		Query:   nil,
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("sign request failed: %v", err)
	}
	headers.Set(core.AuthorizationHeader, signed.Authorization)

	vSHA1 := New(provider,
		WithSignatureAlgorithm(core.NewHMACSHA1()),
		withNowFn(func() time.Time { return now }),
	)
	if _, err := vSHA1.Verify(context.Background(), VerifyInput{
		Method:  "POST",
		Path:    "/api/v1/items",
		Headers: headers,
	}); err != nil {
		t.Fatalf("verify with SHA1 should succeed, got: %v", err)
	}

	vSHA256 := New(provider, withNowFn(func() time.Time { return now }))
	_, err = vSHA256.Verify(context.Background(), VerifyInput{
		Method:  "POST",
		Path:    "/api/v1/items",
		Headers: headers,
	})
	if !errors.Is(err, core.ErrSignatureMismatch) {
		t.Fatalf("expected signature mismatch, got: %v", err)
	}
}

func TestVerifyNonceReplay(t *testing.T) {
	secret := []byte("demo-secret")
	provider := &staticSecretProvider{secret: secret, enabled: true}
	nonceStore := &memoryNonceStore{}

	now := time.Date(2026, 3, 16, 10, 30, 0, 0, time.UTC)
	headers := make(http.Header)
	headers.Set(core.AcceptHeader, "application/json")
	headers.Set(core.DateHeader, now.Format(time.RFC1123))
	headers.Set(core.NonceHeader, "nonce-1")

	s := signer.New()
	signed, err := s.SignRequest("ak-001", secret, core.CanonicalRequestInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("sign request failed: %v", err)
	}
	headers.Set(core.AuthorizationHeader, signed.Authorization)

	v := New(provider,
		WithNonceStore(nonceStore),
		withNowFn(func() time.Time { return now }),
	)
	if _, err := v.Verify(context.Background(), VerifyInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Headers: headers,
	}); err != nil {
		t.Fatalf("first verify should succeed: %v", err)
	}

	_, err = v.Verify(context.Background(), VerifyInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Headers: headers,
	})
	if !errors.Is(err, core.ErrNonceReplayed) {
		t.Fatalf("expected nonce replayed, got: %v", err)
	}
}
