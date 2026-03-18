package fiber

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	fiberV2 "github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"

	"github.com/LatticeBCLab/ak-auth-go/core"
	"github.com/LatticeBCLab/ak-auth-go/signer"
	"github.com/LatticeBCLab/ak-auth-go/verifier"
)

type staticSecretProvider struct {
	secret  []byte
	enabled bool
}

func (p *staticSecretProvider) GetSecret(_ context.Context, _ string) ([]byte, bool, error) {
	return p.secret, p.enabled, nil
}

func TestMiddlewareSuccess(t *testing.T) {
	secret := []byte("demo-secret")
	provider := &staticSecretProvider{
		secret:  secret,
		enabled: true,
	}
	v := verifier.New(provider)
	mw := New(v)

	app := fiberV2.New()
	app.Use(mw.Handler())
	app.Get("/demo", func(c *fiberV2.Ctx) error {
		return c.SendString(c.Locals(LocalAccessKeyID).(string))
	})

	headers := make(http.Header)
	headers.Set(core.AcceptHeader, "application/json")
	headers.Set(core.DateHeader, time.Now().UTC().Format(time.RFC1123))

	q := url.Values{}
	q.Set("page", "1")

	s := signer.New()
	signed, err := s.SignRequest("ak-001", secret, core.CanonicalRequestInput{
		Method:  "GET",
		Path:    "/demo",
		Query:   q,
		Headers: headers,
	})
	assert.NoError(t, err, "sign request should succeed")
	t.Logf("authorization=%s", signed.Authorization)

	req, err := http.NewRequest(http.MethodGet, "/demo?page=1", nil)
	assert.NoError(t, err, "build request should succeed")
	req.Header = headers.Clone()
	req.Header.Set(core.AuthorizationHeader, signed.Authorization)

	resp, err := app.Test(req)
	assert.NoError(t, err, "fiber app test request should succeed")
	if !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err, "read response body should succeed")
	t.Logf("status=%d body=%s", resp.StatusCode, string(body))

	assert.Equal(t, fiberV2.StatusOK, resp.StatusCode)
	assert.Equal(t, "ak-001", string(body))
}

func TestMiddlewareMissingAuthorization(t *testing.T) {
	provider := &staticSecretProvider{secret: []byte("demo-secret"), enabled: true}
	v := verifier.New(provider)
	mw := New(v)

	app := fiberV2.New()
	app.Use(mw.Handler())
	app.Get("/demo", func(c *fiberV2.Ctx) error {
		return c.SendStatus(fiberV2.StatusOK)
	})

	req, err := http.NewRequest(http.MethodGet, "/demo", nil)
	assert.NoError(t, err, "build request should succeed")
	resp, err := app.Test(req)
	assert.NoError(t, err, "fiber app test request should succeed")
	if !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err, "read response body should succeed")
	t.Logf("status=%d body=%s", resp.StatusCode, string(body))

	assert.Equal(t, fiberV2.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), "missing authorization")
}
