package core

import "errors"

const (
	CodeMissingAuthorization      = "ERR_MISSING_AUTHORIZATION"
	CodeInvalidAuthorization      = "ERR_INVALID_AUTHORIZATION_FORMAT"
	CodeAKNotFound                = "ERR_AK_NOT_FOUND"
	CodeAKDisabled                = "ERR_AK_DISABLED"
	CodeMissingDate               = "ERR_MISSING_DATE"
	CodeInvalidDate               = "ERR_INVALID_DATE"
	CodeDateOutOfRange            = "ERR_DATE_OUT_OF_RANGE"
	CodeSignatureMismatch         = "ERR_SIGNATURE_MISMATCH"
	CodeNonceRequired             = "ERR_NONCE_REQUIRED"
	CodeNonceReplayed             = "ERR_NONCE_REPLAYED"
	CodeIPNotAllowed              = "ERR_IP_NOT_ALLOWED"
	CodeNotAuthorized             = "ERR_NOT_AUTHORIZED"
	CodeSecretProviderUnavailable = "ERR_SECRET_PROVIDER_UNAVAILABLE"
	CodeInternal                  = "ERR_INTERNAL"
)

// ErrorCode maps library errors to stable machine-readable error codes.
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrMissingAuthorization):
		return CodeMissingAuthorization
	case errors.Is(err, ErrInvalidAuthorization):
		return CodeInvalidAuthorization
	case errors.Is(err, ErrAKNotFound):
		return CodeAKNotFound
	case errors.Is(err, ErrAKDisabled):
		return CodeAKDisabled
	case errors.Is(err, ErrMissingDate):
		return CodeMissingDate
	case errors.Is(err, ErrInvalidDate):
		return CodeInvalidDate
	case errors.Is(err, ErrDateOutOfRange):
		return CodeDateOutOfRange
	case errors.Is(err, ErrSignatureMismatch):
		return CodeSignatureMismatch
	case errors.Is(err, ErrNonceRequired):
		return CodeNonceRequired
	case errors.Is(err, ErrNonceReplayed):
		return CodeNonceReplayed
	case errors.Is(err, ErrIPNotAllowed):
		return CodeIPNotAllowed
	case errors.Is(err, ErrNotAuthorized):
		return CodeNotAuthorized
	case errors.Is(err, ErrSecretProviderUnavailable):
		return CodeSecretProviderUnavailable
	default:
		return CodeInternal
	}
}
