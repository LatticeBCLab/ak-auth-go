package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorCode(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrMissingAuthorization, CodeMissingAuthorization},
		{ErrInvalidAuthorization, CodeInvalidAuthorization},
		{ErrAKNotFound, CodeAKNotFound},
		{ErrAKDisabled, CodeAKDisabled},
		{ErrMissingDate, CodeMissingDate},
		{ErrInvalidDate, CodeInvalidDate},
		{ErrDateOutOfRange, CodeDateOutOfRange},
		{ErrSignatureMismatch, CodeSignatureMismatch},
		{ErrNonceRequired, CodeNonceRequired},
		{ErrNonceReplayed, CodeNonceReplayed},
		{ErrIPNotAllowed, CodeIPNotAllowed},
		{ErrNotAuthorized, CodeNotAuthorized},
		{ErrSecretProviderUnavailable, CodeSecretProviderUnavailable},
	}

	for _, tc := range cases {
		got := ErrorCode(tc.err)
		t.Logf("err=%v code=%s", tc.err, got)
		assert.Equal(t, tc.want, got, "error code should match mapping")
	}
}
