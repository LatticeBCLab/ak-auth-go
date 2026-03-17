package fiber

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	fiberV2 "github.com/gofiber/fiber/v2"

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
	if err != nil {
		t.Fatalf("sign request failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "/demo?page=1", nil)
	if err != nil {
		t.Fatalf("build request failed: %v", err)
	}
	req.Header = headers.Clone()
	req.Header.Set(core.AuthorizationHeader, signed.Authorization)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("test request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiberV2.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ak-001" {
		t.Fatalf("unexpected body: %s", string(body))
	}
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
	if err != nil {
		t.Fatalf("build request failed: %v", err)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("test request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiberV2.StatusUnauthorized {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "missing authorization") {
		t.Fatalf("unexpected body: %s", string(body))
	}
}
