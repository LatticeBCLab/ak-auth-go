package core

import (
	"errors"
	"net/http"
	"net/url"
	"time"
)

const (
	AuthorizationHeader = "Authorization"
	DateHeader          = "Date"
	AcceptHeader        = "Accept"
	ContentMD5Header    = "Content-MD5"
	ContentTypeHeader   = "Content-Type"
	NonceHeader         = "x-acs-signature-nonce"
)

var (
	ErrMissingAuthorization      = errors.New("missing authorization header")
	ErrInvalidAuthorization      = errors.New("invalid authorization header format")
	ErrAKNotFound                = errors.New("access key not found")
	ErrAKDisabled                = errors.New("access key disabled")
	ErrMissingDate               = errors.New("missing date header")
	ErrInvalidDate               = errors.New("invalid date header")
	ErrDateOutOfRange            = errors.New("date out of allowed clock skew")
	ErrSignatureMismatch         = errors.New("signature mismatch")
	ErrNonceRequired             = errors.New("nonce required")
	ErrNonceReplayed             = errors.New("nonce replayed")
	ErrIPNotAllowed              = errors.New("ip not allowed")
	ErrNotAuthorized             = errors.New("not authorized")
	ErrSecretProviderUnavailable = errors.New("secret provider unavailable")
)

// SignatureAlgorithm signs the message bytes with the given secret.
type SignatureAlgorithm interface {
	Name() string
	Sign(secret []byte, message []byte) ([]byte, error)
}

// CanonicalRequestInput is the transport-neutral request input for canonicalization.
type CanonicalRequestInput struct {
	Method  string
	Path    string
	Query   url.Values
	Headers http.Header
}

func DateLayout() string {
	return time.RFC1123
}
