package oauth

import (
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

var (
	ErrMultipleRedirectUri = spi.ErrInvalidRequest("multiple redirect_uri registered, but none selected.")
	ErrNoRedirectUri = spi.ErrInvalidRequest("no redirect_uri registered, and none provided.")
)

// This function implements the OAuth 2.0 specification logic for selecting a redirect_uri to use.
func SelectRedirectUri(supplied string, registered []string) (string, error) {
	if len(supplied) == 0 {
		if len(registered) != 1 {
			return "", ErrMultipleRedirectUri
		} else {
			return registered[0], nil
		}
	} else {
		if !funk.ContainsString(registered, supplied) {
			return "", ErrNoRedirectUri
		} else {
			return supplied, nil
		}
	}
}
