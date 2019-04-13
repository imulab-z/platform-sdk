package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"net/http"
)

var (
	_ ClientAuthentication = (*ClientSecretPostAuthentication)(nil)
)

// Implementation of client_secret_post authentication method. Although client_secret_post is officially defined in
// Open ID Connect 1.0 documents, but it's still widely used in OAuth 2.0. This implementation assumes ClientLookup
// will return a client that implements ClientSecretAware interface.
type ClientSecretPostAuthentication struct {
	Lookup 				spi.ClientLookup

	// String comparator to compare secret with. Supplied secret will
	// be called as first argument; registered secret will be called
	// as second argument.
	//
	// If this is left nil, defaults to string equality comparison
	SecretComparator	Comparator
}

func (a *ClientSecretPostAuthentication) Method() string {
	return spi.AuthMethodClientSecretPost
}

func (a *ClientSecretPostAuthentication) Supports(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}

	if err := r.ParseForm(); err != nil {
		return false
	}

	return len(r.PostForm.Get(spi.ParamClientId)) > 0 && len(r.PostForm.Get(spi.ParamClientSecret)) > 0
}

func (a *ClientSecretPostAuthentication) Authenticate(ctx context.Context, r *http.Request) (spi.OAuthClient, error) {
	clientId, suppliedSecret, err := ParseClientIdAndSecretFromPostRequest(r)
	if err != nil {
		return nil, a.failed(err.Error())
	}

	client, registeredSecret, err := GetClientSecret(ctx, a.Lookup, clientId)
	if err != nil {
		return nil, a.failed(err.Error())
	}

	if equals := a.compareSecret(suppliedSecret, registeredSecret); !equals {
		return nil, a.failed("authentication failed")
	}

	return client, nil
}

func (a *ClientSecretPostAuthentication) compareSecret(supplied, registered string) bool {
	if a.SecretComparator != nil {
		return a.SecretComparator(supplied, registered)
	}
	return supplied == registered
}

func (a *ClientSecretPostAuthentication) failed(reason string) error {
	return spi.ErrInvalidClient(reason, "")
}