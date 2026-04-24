package main

import (
	"context"
	"fmt"
	"log"
	"os"

	fiberV3 "github.com/gofiber/fiber/v3"

	akfiber "github.com/LatticeBCLab/ak-auth-go/server/fiber"
	"github.com/LatticeBCLab/ak-auth-go/verifier"
)

type envSecretProvider struct{}

func (p *envSecretProvider) GetSecret(ctx context.Context, accessKeyID string) ([]byte, bool, error) {
	_ = ctx
	if accessKeyID != "demo-ak" {
		return nil, false, nil
	}
	secret := os.Getenv("AK_DEMO_SECRET")
	if secret == "" {
		secret = "demo-secret"
	}
	return []byte(secret), true, nil
}

func main() {
	app := fiberV3.New()

	v := verifier.New(&envSecretProvider{})
	app.Use(akfiber.New(v).Handler())

	app.Get("/hello", func(c fiberV3.Ctx) error {
		ak := c.Locals(akfiber.LocalAccessKeyID)
		alg := c.Locals(akfiber.LocalAlgorithm)
		return c.JSON(fiberV3.Map{
			"message": "hello from protected endpoint",
			"ak":      ak,
			"alg":     alg,
		})
	})

	addr := ":8080"
	fmt.Printf("fiber example listening on %s\n", addr)
	log.Fatal(app.Listen(addr))
}
