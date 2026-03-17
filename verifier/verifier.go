package verifier

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LatticeBCLab/ak-auth-go/core"
)

type SecretProvider interface {
	GetSecret(ctx context.Context, accessKeyID string) (secret []byte, enabled bool, err error)
}

type NonceStore interface {
	UseNonce(ctx context.Context, accessKeyID, nonce string, ttl time.Duration) (firstSeen bool, err error)
}

type IPPolicy interface {
	Allow(ctx context.Context, accessKeyID, clientIP string) (bool, error)
}

type Authorizer interface {
	Allow(ctx context.Context, in VerifyInput, result *VerifyResult) (bool, error)
}

type VerifyInput struct {
	Method   string
	Path     string
	Query    url.Values
	Headers  http.Header
	ClientIP string
}

type VerifyResult struct {
	AccessKeyID  string
	Algorithm    string
	StringToSign string
	Signature    string
	SignedAt     time.Time
}

type Option func(*Verifier)

type Verifier struct {
	secretProvider SecretProvider
	algorithm      core.SignatureAlgorithm
	clockSkew      time.Duration
	nonceTTL       time.Duration
	nonceStore     NonceStore
	ipPolicy       IPPolicy
	authorizer     Authorizer
	nowFn          func() time.Time
}

func New(secretProvider SecretProvider, opts ...Option) *Verifier {
	v := &Verifier{
		secretProvider: secretProvider,
		algorithm:      core.NewHMACSHA256(),
		clockSkew:      15 * time.Minute,
		nowFn:          time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.nonceTTL <= 0 {
		v.nonceTTL = v.clockSkew * 2
		if v.nonceTTL <= 0 {
			v.nonceTTL = 30 * time.Minute
		}
	}
	return v
}

func WithSignatureAlgorithm(alg core.SignatureAlgorithm) Option {
	return func(v *Verifier) {
		if alg != nil {
			v.algorithm = alg
		}
	}
}

func WithClockSkew(skew time.Duration) Option {
	return func(v *Verifier) {
		if skew > 0 {
			v.clockSkew = skew
		}
	}
}

func WithNonceStore(store NonceStore) Option {
	return func(v *Verifier) {
		v.nonceStore = store
	}
}

func WithNonceTTL(ttl time.Duration) Option {
	return func(v *Verifier) {
		if ttl > 0 {
			v.nonceTTL = ttl
		}
	}
}

func WithIPPolicy(policy IPPolicy) Option {
	return func(v *Verifier) {
		v.ipPolicy = policy
	}
}

func WithAuthorizer(authorizer Authorizer) Option {
	return func(v *Verifier) {
		v.authorizer = authorizer
	}
}

func withNowFn(nowFn func() time.Time) Option {
	return func(v *Verifier) {
		if nowFn != nil {
			v.nowFn = nowFn
		}
	}
}

func (v *Verifier) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	if v.secretProvider == nil {
		return nil, core.ErrSecretProviderUnavailable
	}

	ak, clientSig, err := parseAuthorizationHeader(in.Headers)
	if err != nil {
		return nil, err
	}

	signedAt, err := parseDateHeader(in.Headers)
	if err != nil {
		return nil, err
	}

	if outOfSkew(v.nowFn(), signedAt, v.clockSkew) {
		return nil, core.ErrDateOutOfRange
	}

	secret, enabled, err := v.secretProvider.GetSecret(ctx, ak)
	if err != nil {
		if err == core.ErrAKNotFound {
			return nil, core.ErrAKNotFound
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}
	if !enabled {
		return nil, core.ErrAKDisabled
	}

	if v.nonceStore != nil {
		nonce := strings.TrimSpace(in.Headers.Get(core.NonceHeader))
		if nonce == "" {
			return nil, core.ErrNonceRequired
		}
		firstSeen, err := v.nonceStore.UseNonce(ctx, ak, nonce, v.nonceTTL)
		if err != nil {
			return nil, fmt.Errorf("nonce store: %w", err)
		}
		if !firstSeen {
			return nil, core.ErrNonceReplayed
		}
	}

	if v.ipPolicy != nil {
		allowed, err := v.ipPolicy.Allow(ctx, ak, in.ClientIP)
		if err != nil {
			return nil, fmt.Errorf("ip policy: %w", err)
		}
		if !allowed {
			return nil, core.ErrIPNotAllowed
		}
	}

	stringToSign := core.BuildStringToSign(core.CanonicalRequestInput{
		Method:  in.Method,
		Path:    in.Path,
		Query:   in.Query,
		Headers: in.Headers,
	})

	raw, err := v.algorithm.Sign(secret, []byte(stringToSign))
	if err != nil {
		return nil, fmt.Errorf("compute signature: %w", err)
	}
	expectedSig := base64.StdEncoding.EncodeToString(raw)
	if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(clientSig)) != 1 {
		return nil, core.ErrSignatureMismatch
	}

	result := &VerifyResult{
		AccessKeyID:  ak,
		Algorithm:    v.algorithm.Name(),
		StringToSign: stringToSign,
		Signature:    expectedSig,
		SignedAt:     signedAt,
	}

	if v.authorizer != nil {
		allowed, err := v.authorizer.Allow(ctx, in, result)
		if err != nil {
			return nil, fmt.Errorf("authorize: %w", err)
		}
		if !allowed {
			return nil, core.ErrNotAuthorized
		}
	}

	return result, nil
}

func parseAuthorizationHeader(headers http.Header) (accessKeyID, signature string, err error) {
	authorization := strings.TrimSpace(headers.Get(core.AuthorizationHeader))
	if authorization == "" {
		return "", "", core.ErrMissingAuthorization
	}

	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "acs") {
		return "", "", core.ErrInvalidAuthorization
	}

	cred := strings.SplitN(strings.TrimSpace(parts[1]), ":", 2)
	if len(cred) != 2 {
		return "", "", core.ErrInvalidAuthorization
	}

	accessKeyID = strings.TrimSpace(cred[0])
	signature = strings.TrimSpace(cred[1])
	if accessKeyID == "" || signature == "" {
		return "", "", core.ErrInvalidAuthorization
	}

	return accessKeyID, signature, nil
}

func parseDateHeader(headers http.Header) (time.Time, error) {
	date := strings.TrimSpace(headers.Get(core.DateHeader))
	if date == "" {
		return time.Time{}, core.ErrMissingDate
	}
	t, err := time.Parse(core.DateLayout(), date)
	if err != nil {
		return time.Time{}, core.ErrInvalidDate
	}
	return t, nil
}

func outOfSkew(now, signedAt time.Time, skew time.Duration) bool {
	delta := now.Sub(signedAt)
	if delta < 0 {
		delta = -delta
	}
	return delta > skew
}
