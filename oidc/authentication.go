package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"net/http"
)

// Main entry point for token endpoint authentication
type AuthenticationHandler struct {
	Authenticators	map[string]oauth.ClientAuthentication
	ClientLookup 	spi.ClientLookup
}

func (h *AuthenticationHandler) Authenticate(ctx context.Context, r *http.Request) (spi.OAuthClient, error) {
	client := h.tryOidcClient(ctx, r)

	// pinpoint authenticator
	if client != nil {
		if auth, ok := h.Authenticators[client.GetTokenEndpointAuthMethod()]; !ok {
			return nil, spi.ErrServerErrorf("failed to locate proper authenticator")
		} else {
			return auth.Authenticate(ctx, r)
		}
	}

	// try authenticators
	var lastError error
	for _, auth := range h.Authenticators {
		if !auth.Supports(r) {
			continue
		}

		if client, err := auth.Authenticate(ctx, r); err != nil {
			lastError = err
			continue
		} else {
			return client, nil
		}
	}

	if lastError == nil {
		return nil, spi.ErrServerErrorf("failed to locate proper authenticator")
	} else {
		return nil, lastError
	}
}

func (h *AuthenticationHandler) tryOidcClient(ctx context.Context, r *http.Request) spi.OidcClient {
	if err := r.ParseForm(); err != nil {
		return nil
	}

	if clientId := r.PostForm.Get(spi.ParamClientId); len(clientId) == 0 {
		return nil
	} else if client, err := h.ClientLookup.FindById(ctx, clientId); err != nil {
		return nil
	} else if oidcClient, ok := client.(spi.OidcClient); !ok {
		return nil
	} else {
		return oidcClient
	}
}
