package fiber

import (
	"errors"
	"net/http"
	"net/url"

	fiberV2 "github.com/gofiber/fiber/v2"

	"github.com/LatticeBCLab/ak-auth-go/core"
	"github.com/LatticeBCLab/ak-auth-go/verifier"
)

const (
	LocalAccessKeyID = "ak_access_key_id"
	LocalAlgorithm   = "ak_algorithm"
)

type ErrorHandler func(c *fiberV2.Ctx, err error) error

type Option func(*Middleware)

type Middleware struct {
	verifier     *verifier.Verifier
	errorHandler ErrorHandler
}

func New(v *verifier.Verifier, opts ...Option) *Middleware {
	m := &Middleware{
		verifier:     v,
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithErrorHandler(handler ErrorHandler) Option {
	return func(m *Middleware) {
		if handler != nil {
			m.errorHandler = handler
		}
	}
}

func (m *Middleware) Handler() fiberV2.Handler {
	return func(c *fiberV2.Ctx) error {
		headers := make(http.Header)
		for k, vals := range c.GetReqHeaders() {
			for _, v := range vals {
				headers.Add(k, v)
			}
		}

		query, err := url.ParseQuery(string(c.Request().URI().QueryString()))
		if err != nil {
			return m.errorHandler(c, err)
		}

		result, err := m.verifier.Verify(c.UserContext(), verifier.VerifyInput{
			Method:   c.Method(),
			Path:     c.Path(),
			Query:    query,
			Headers:  headers,
			ClientIP: c.IP(),
		})
		if err != nil {
			return m.errorHandler(c, err)
		}

		c.Locals(LocalAccessKeyID, result.AccessKeyID)
		c.Locals(LocalAlgorithm, result.Algorithm)

		return c.Next()
	}
}

func defaultErrorHandler(c *fiberV2.Ctx, err error) error {
	status := fiberV2.StatusInternalServerError
	message := err.Error()

	switch {
	case errors.Is(err, core.ErrMissingAuthorization):
		status = fiberV2.StatusUnauthorized
	case errors.Is(err, core.ErrInvalidAuthorization),
		errors.Is(err, core.ErrMissingDate),
		errors.Is(err, core.ErrInvalidDate),
		errors.Is(err, core.ErrNonceRequired):
		status = fiberV2.StatusBadRequest
	case errors.Is(err, core.ErrAKNotFound),
		errors.Is(err, core.ErrAKDisabled),
		errors.Is(err, core.ErrDateOutOfRange),
		errors.Is(err, core.ErrSignatureMismatch),
		errors.Is(err, core.ErrNonceReplayed),
		errors.Is(err, core.ErrIPNotAllowed),
		errors.Is(err, core.ErrNotAuthorized):
		status = fiberV2.StatusForbidden
	}

	return c.Status(status).JSON(fiberV2.Map{
		"code":       status,
		"error_code": core.ErrorCode(err),
		"success":    false,
		"message":    message,
	})
}
