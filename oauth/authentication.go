package oauth

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/imulab-z/platform-sdk/spi"
	"net/http"
	"strings"
)

const (
	Basic               = "Basic"
	Space               = " "
	AuthorizationHeader = "Authorization"
)

// This is the common interface for implementing client authentication functions. The SDK
// only provides non-interaction based implementation, which works by fetching client through
// ClientLookup interface and perform authentication with information readily available within
// the client.
// If the architecture of choice requires reaching out to an external service (e.g. client-service)
// for authentication, users need to roll their own implementations.
type ClientAuthentication interface {
	// Perform authentication on the request
	Authenticate(ctx context.Context, r *http.Request) (spi.OAuthClient, error)
	// Returns the authentication method it supports
	Method() string
	// Returns true if the given authentication implementation can attempt process the request.
	Supports(r *http.Request) bool
}

// Utility function to get client secret from spi.ClientLookup by the client's id. In order to produce a secret, the client
// returned by spi.ClientLookup must implement spi.ClientSecretAware interface.
//
// This method is exposed to reduce the work of rolling out custom ClientAuthentication implementation.
func GetClientSecret(ctx context.Context, lookup spi.ClientLookup, clientId string) (spi.OAuthClient, string, error) {
	client, err := lookup.FindById(ctx, clientId)
	if err != nil {
		return nil, "", err
	}

	if secretAwareClient, ok := client.(spi.ClientSecretAware); !ok {
		return nil, "", errors.New("client secret is not available for comparison")
	} else {
		return client, secretAwareClient.GetSecret(), nil
	}
}

// Utility function to extract username and password as client id and client secret respectively from the HTTP
// Authorization header.
//
// This method is exposed to reduce the work of rolling out custom ClientAuthentication implementation.
func ParseAuthorizationHeader(r *http.Request) (id, secret string, err error) {
	headerValue := r.Header.Get("Authorization")

	switch {
	case len(headerValue) == 0:
		err = errors.New("missing Authorization header")
		return
	case !strings.HasPrefix(headerValue, Basic+ Space):
		err = errors.New("invalid Authorization header scheme")
		return
	}

	headerValue = strings.TrimPrefix(headerValue, Basic+ Space)
	if decoded, e := base64.StdEncoding.DecodeString(headerValue); e != nil {
		err = errors.New("invalid Authorization header encoding")
		return
	} else {
		headerValue = string(decoded)
	}

	parts := strings.Split(headerValue, ":")
	if len(parts) != 2 {
		err = errors.New("invalid Authorization header content format")
		return
	}

	id = parts[0]
	secret = parts[1]
	err = nil
	return
}

// Utility function to extract client_id and client_secret from the HTTP POST form.
//
// This method is exposed to reduce the work of rolling out custom ClientAuthentication implementation.
func ParseClientIdAndSecretFromPostRequest(r *http.Request) (id, secret string, err error) {
	if http.MethodPost != r.Method {
		err = errors.New("only POST method is supported")
		return
	}

	if e := r.ParseForm(); e != nil {
		err = e
		return
	}

	id = r.PostForm.Get(spi.ParamClientId)
	secret = r.PostForm.Get(spi.ParamClientSecret)
	err = nil
	return
}