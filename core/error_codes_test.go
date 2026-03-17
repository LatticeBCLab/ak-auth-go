package core

import "testing"

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
		if got := ErrorCode(tc.err); got != tc.want {
			t.Fatalf("error code mismatch for %v, got %s, want %s", tc.err, got, tc.want)
		}
	}
}
