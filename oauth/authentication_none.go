package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"net/http"
)

var (
	_ ClientAuthentication = (*NoneAuthentication)(nil)
)

// This authenticator implements the logic to allow public clients to pass authentication.
type NoneAuthentication struct {
	Lookup 	spi.ClientLookup
}

func (a *NoneAuthentication) Method() string {
	return spi.AuthMethodNone
}

func (a *NoneAuthentication) Supports(r *http.Request) bool {
	return true
}

func (a *NoneAuthentication) Authenticate(ctx context.Context, r *http.Request) (spi.OAuthClient, error) {
	clientId, err := a.getClientId(r)
	if err != nil {
		return nil, a.failed(err.Error())
	}

	client, err := a.Lookup.FindById(ctx, clientId)
	if err != nil {
		return nil, a.failed(err.Error())
	}

	if client.GetType() != spi.ClientTypePublic {
		return nil, a.failed("authentication is required for non-public clients.")
	}

	return client, nil
}

func (a *NoneAuthentication) getClientId(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", err
	} else {
		return r.Form.Get(spi.ParamClientId), nil
	}
}

func (a *NoneAuthentication) failed(reason string) error {
	return spi.ErrInvalidClient(reason, "")
}