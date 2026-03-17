package core

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

func NewHMACSHA256() SignatureAlgorithm {
	return &hmacSHA256{}
}

func NewHMACSHA1() SignatureAlgorithm {
	return &hmacSHA1{}
}

func NewHMACSHA512() SignatureAlgorithm {
	return &hmacSHA512{}
}

type hmacSHA256 struct{}

func (h *hmacSHA256) Name() string { return "HMAC-SHA256" }
func (h *hmacSHA256) Sign(secret []byte, message []byte) ([]byte, error) {
	m := hmac.New(sha256.New, secret)
	_, _ = m.Write(message)
	return m.Sum(nil), nil
}

type hmacSHA1 struct{}

func (h *hmacSHA1) Name() string { return "HMAC-SHA1" }
func (h *hmacSHA1) Sign(secret []byte, message []byte) ([]byte, error) {
	m := hmac.New(sha1.New, secret)
	_, _ = m.Write(message)
	return m.Sum(nil), nil
}

type hmacSHA512 struct{}

func (h *hmacSHA512) Name() string { return "HMAC-SHA512" }
func (h *hmacSHA512) Sign(secret []byte, message []byte) ([]byte, error) {
	m := hmac.New(sha512.New, secret)
	_, _ = m.Write(message)
	return m.Sum(nil), nil
}
