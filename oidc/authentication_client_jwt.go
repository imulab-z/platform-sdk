package oidc

import (
	"context"
	"errors"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"time"
)

var (
	_ oauth.ClientAuthentication = (*ClientSecretJwtAuthentication)(nil)
)

// Implementation of ClientAuthentication to handle client_secret_jwt authentication method. This implementation
// assumes the client returned by ClientLookup implements ClientSecretAware interface and the secret returned is
// plain text or could be converted back to plain text through the SecretConversionFunc.
type ClientSecretJwtAuthentication struct {
	Lookup               spi.ClientLookup
	SecretConversionFunc func(stored string) string
	TokenEndpointUrl     string
}

func (a *ClientSecretJwtAuthentication) Method() string {
	return spi.AuthMethodClientSecretJwt
}

func (a *ClientSecretJwtAuthentication) Supports(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}

	return len(r.PostForm.Get(spi.ParamClientAssertion)) > 0 &&
		len(r.PostForm.Get(spi.ParamClientAssertionType)) > 0
}

func (a *ClientSecretJwtAuthentication) Authenticate(ctx context.Context, r *http.Request) (spi.OAuthClient, error) {
	assertion, err := a.getClientAssertion(r)
	if err != nil {
		return nil, a.failed(err.Error())
	}

	client, err := a.getClient(ctx, assertion, r)
	if err != nil {
		return nil, a.failed(err.Error())
	}

	if err := a.validateAssertion(ctx, assertion, client); err != nil {
		return nil, a.failed(err.Error())
	}

	return client, nil
}

// extract client_assertion from request body
func (a *ClientSecretJwtAuthentication) getClientAssertion(r *http.Request) (string, error) {
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
func (a *ClientSecretJwtAuthentication) getClient(ctx context.Context, assertion string, r *http.Request) (spi.OAuthClient, error) {
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
	} else {
		return client, nil
	}
}

// validate client_assertion against the client.
func (a *ClientSecretJwtAuthentication) validateAssertion(ctx context.Context, assertion string, client spi.OAuthClient) error {
	secret, err := a.resolveSecret(client)
	if err != nil {
		return err
	}

	claims, err := a.resolveClaims(assertion, secret, client)
	if err != nil {
		return err
	}

	if err := a.validateClaims(claims, client); err != nil {
		return err
	}

	return nil
}

func (a *ClientSecretJwtAuthentication) resolveSecret(client spi.OAuthClient) (string, error) {
	if secretAware, ok := client.(spi.ClientSecretAware); !ok {
		return "", errors.New("client secret is not available for comparison")
	} else {
		secret := secretAware.GetSecret()
		if a.SecretConversionFunc != nil {
			secret = a.SecretConversionFunc(secret)
		}
		return secret, nil
	}
}

// Obtains JWT claims from the given assertion. If necessary, the signing algorithm is checked against registered value.
func (a *ClientSecretJwtAuthentication) resolveClaims(assertion string, secret string, client spi.OAuthClient) (*jwt.Claims, error) {
	claims := &jwt.Claims{}

	tok, err := jwt.ParseSigned(assertion)
	if err != nil {
		return nil, err
	}

	// check signing algorithm when the client is an OidcClient.
	if _, ok := client.(spi.OidcClient); ok {
		for _, header := range tok.Headers {
			if len(header.Algorithm) > 0 && header.Algorithm != client.(spi.OidcClient).GetTokenEndpointAuthSigningAlg() {
				return nil, errors.New("client_assertion signing algorithm mismatch with token_endpoint_auth_signing_alg")
			}
		}
	}

	if err := tok.Claims([]byte(secret), claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func (a *ClientSecretJwtAuthentication) validateClaims(claims *jwt.Claims, client spi.OAuthClient) error {
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: client.GetId(),
		Subject: client.GetId(),
		Audience: jwt.Audience{a.TokenEndpointUrl},
	}, 5*time.Second); err != nil {
		return err
	}
	return nil
}

func (a *ClientSecretJwtAuthentication) failed(reason string) error {
	return spi.ErrInvalidClient(reason, "")
}

