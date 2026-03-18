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
	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err, "sign request should succeed")
	headers.Set(core.AuthorizationHeader, signed.Authorization)
	t.Logf("authorization=%s", signed.Authorization)

	v := New(provider, withNowFn(func() time.Time { return now }))
	res, err := v.Verify(context.Background(), VerifyInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Query:   q,
		Headers: headers,
	})
	assert.NoError(t, err, "verify should succeed")
	t.Logf("verify result: accessKeyID=%s algorithm=%s", res.AccessKeyID, res.Algorithm)
	assert.Equal(t, "ak-001", res.AccessKeyID)
	assert.Equal(t, "HMAC-SHA256", res.Algorithm)
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
	assert.NoError(t, err, "sign request with SHA1 should succeed")
	headers.Set(core.AuthorizationHeader, signed.Authorization)
	t.Logf("sha1 authorization=%s", signed.Authorization)

	vSHA1 := New(provider,
		WithSignatureAlgorithm(core.NewHMACSHA1()),
		withNowFn(func() time.Time { return now }),
	)
	_, err = vSHA1.Verify(context.Background(), VerifyInput{
		Method:  "POST",
		Path:    "/api/v1/items",
		Headers: headers,
	})
	assert.NoError(t, err, "verify with SHA1 should succeed")

	vSHA256 := New(provider, withNowFn(func() time.Time { return now }))
	_, err = vSHA256.Verify(context.Background(), VerifyInput{
		Method:  "POST",
		Path:    "/api/v1/items",
		Headers: headers,
	})
	t.Logf("sha256 verify error=%v", err)
	assert.True(t, errors.Is(err, core.ErrSignatureMismatch), "verify with mismatched algorithm should fail with signature mismatch")
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
	assert.NoError(t, err, "sign request should succeed")
	headers.Set(core.AuthorizationHeader, signed.Authorization)
	t.Logf("nonce=%s authorization=%s", headers.Get(core.NonceHeader), signed.Authorization)

	v := New(provider,
		WithNonceStore(nonceStore),
		withNowFn(func() time.Time { return now }),
	)
	_, err = v.Verify(context.Background(), VerifyInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Headers: headers,
	})
	assert.NoError(t, err, "first verify should succeed")

	_, err = v.Verify(context.Background(), VerifyInput{
		Method:  "GET",
		Path:    "/api/v1/items",
		Headers: headers,
	})
	t.Logf("second verify error=%v", err)
	assert.True(t, errors.Is(err, core.ErrNonceReplayed), "second verify with same nonce should be replayed")
}
