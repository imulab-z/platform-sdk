package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"strings"
	"time"
)

var (
	_ oauth.ClientAuthentication = (*PrivateKeyJwtAuthentication)(nil)
)

type PrivateKeyJwtAuthentication struct {
	Lookup           spi.ClientLookup
	TokenEndpointUrl string
}

func (a *PrivateKeyJwtAuthentication) Method() string {
	return spi.AuthMethodPrivateKeyJwt
}

func (a *PrivateKeyJwtAuthentication) Supports(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}

	return len(r.PostForm.Get(spi.ParamClientAssertion)) > 0 &&
		len(r.PostForm.Get(spi.ParamClientAssertionType)) > 0
}

func (a *PrivateKeyJwtAuthentication) Authenticate(ctx context.Context, r *http.Request) (spi.OAuthClient, error) {
	assertion, err := a.getClientAssertion(r)
	if err != nil {
		return nil, a.failed(err.Error())
	}

	client, err := a.getClient(ctx, assertion, r)
	if err != nil {
		return nil, a.failed(err.Error())
	}

	if err := a.validateJwt(ctx, assertion, client); err != nil {
		return nil, a.failed(err.Error())
	}

	return client, nil
}

func (a *PrivateKeyJwtAuthentication) getClientAssertion(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", err
	}

	if r.PostForm.Get(spi.ParamClientAssertionType) != spi.ClientAssertionTypeJwtBearer {
		return "", spi.ErrInvalidRequest("invalid client_assertion_type")
	}

	if assertion := r.PostForm.Get(spi.ParamClientAssertion); len(assertion) == 0 {
		return "", spi.ErrInvalidRequest("missing client_assertion")
	} else {
		return assertion, nil
	}
}

// Try to retrieve the client by its id deduced from either client_id parameter or the assertion JWT.
//
// If the request provided client_id in addition to client_assertion, we can avoid the rather slow call to parse JWT
// without key verification.
func (a *PrivateKeyJwtAuthentication) getClient(ctx context.Context, assertion string, r *http.Request) (spi.OidcClient, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	var clientId = r.PostForm.Get(spi.ParamClientId)

	if len(clientId) == 0 {
		claims := make(map[string]interface{})

		if tok, err := jwt.ParseSigned(assertion); err != nil {
			return nil, err
		} else if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return nil, err
		}

		if sub, ok := claims["sub"].(string); !ok {
			return nil, spi.ErrInvalidRequest("invalid client_assertion: sub is not a string")
		} else {
			clientId = sub
		}
	}

	if client, err := a.Lookup.FindById(ctx, clientId); err != nil {
		return nil, err
	} else if oidcClient, ok := client.(spi.OidcClient); !ok {
		return nil, spi.ErrServerErrorf("client is not a spi.OidcClient")
	} else {
		return oidcClient, nil
	}
}

// Validate the given JWT against client's registered verification key, assuming the key is retrievable via
// OidcClient#GetJwks()
func (a *PrivateKeyJwtAuthentication) validateJwt(ctx context.Context, assertion string, client spi.OidcClient) error {
	claims := &jwt.Claims{}

	tok, err := jwt.ParseSigned(assertion)
	if err != nil {
		return err
	}

	for _, header := range tok.Headers {
		if len(header.Algorithm) > 0 && header.Algorithm != client.GetTokenEndpointAuthSigningAlg() {
			return errors.New("client_assertion signing algorithm mismatch with token_endpoint_auth_signing_alg")
		}
	}

	jwks := &jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 0),
	}
	if err := json.NewDecoder(strings.NewReader(client.GetJwks())).Decode(jwks); err != nil {
		return err
	}
	if err := tok.Claims(jwks, claims); err != nil {
		return err
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:   client.GetId(),
		Subject:  client.GetId(),
		Audience: jwt.Audience{a.TokenEndpointUrl},
	}, 5*time.Second); err != nil {
		return err
	}

	return nil
}

func (a *PrivateKeyJwtAuthentication) failed(reason string) error {
	return spi.ErrInvalidClient(reason, "")
}
