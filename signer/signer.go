package signer

import (
	"encoding/base64"
	"fmt"

	"github.com/LatticeBCLab/ak-auth-go/core"
)

const authorizationPrefix = "acs"

type Option func(*Signer)

type Signer struct {
	algorithm core.SignatureAlgorithm
}

type SignedRequest struct {
	Authorization string
	Signature     string
	StringToSign  string
	Algorithm     string
}

func New(opts ...Option) *Signer {
	s := &Signer{algorithm: core.NewHMACSHA256()}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithSignatureAlgorithm(alg core.SignatureAlgorithm) Option {
	return func(s *Signer) {
		if alg != nil {
			s.algorithm = alg
		}
	}
}

func (s *Signer) Algorithm() core.SignatureAlgorithm {
	return s.algorithm
}

func (s *Signer) Sign(secret []byte, stringToSign string) (string, error) {
	raw, err := s.algorithm.Sign(secret, []byte(stringToSign))
	if err != nil {
		return "", fmt.Errorf("sign failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (s *Signer) BuildAuthorization(accessKeyID, signature string) string {
	return fmt.Sprintf("%s %s:%s", authorizationPrefix, accessKeyID, signature)
}

func (s *Signer) SignRequest(accessKeyID string, secret []byte, in core.CanonicalRequestInput) (*SignedRequest, error) {
	stringToSign := core.BuildStringToSign(in)
	signature, err := s.Sign(secret, stringToSign)
	if err != nil {
		return nil, err
	}

	return &SignedRequest{
		Authorization: s.BuildAuthorization(accessKeyID, signature),
		Signature:     signature,
		StringToSign:  stringToSign,
		Algorithm:     s.algorithm.Name(),
	}, nil
}
