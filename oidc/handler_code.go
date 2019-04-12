package oidc

import (
	"context"
	"errors"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
)

var (
	_ oauth.AuthorizeHandler = (*AuthorizeCodeHandler)(nil)
	_ oauth.TokenHandler = (*AuthorizeCodeHandler)(nil)
)

// This handler implements oauth.AuthorizeHandler for the OpenID Connect 1.0 addition of the authorization code flow.
// It should be used in combination with (placed after) the oauth.AuthorizeCodeHandler. In addition, it assumes the
// AuthorizeCodeRepository implementation used by the oauth.AuthorizeCodeHandler was capable of storing the oidc.Session,
// so that this handler will NOT attempt to store the request session again.
type AuthorizeCodeHandler struct {
	IdTokenHelper	*IdTokenHelper
}

func (h *AuthorizeCodeHandler) Authorize(ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error {
	if !h.SupportsAuthorizeRequest(req) {
		return nil
	}

	if len(resp.GetString(oauth.Code)) == 0 {
		return spi.ErrServerError(errors.New("authorize code was not generated"))
	}

	// assuming oauth.AuthorizeCodeHandler had already stored the request with oidc.Session

	req.HandledResponseType(spi.ResponseTypeCode)

	return nil
}

func (h *AuthorizeCodeHandler) SupportsAuthorizeRequest(req oauth.AuthorizeRequest) bool {
	return oauth.V(req.GetResponseTypes()).ContainsExactly(spi.ResponseTypeCode)
}

func (h *AuthorizeCodeHandler) UpdateSession(ctx context.Context, req oauth.TokenRequest) error {
	// assuming oauth.AuthorizeCodeHandler had already updated the session with oidc.Session
	return nil
}

func (h *AuthorizeCodeHandler) IssueToken(ctx context.Context, req oauth.TokenRequest, resp oauth.Response) error {
	if !h.SupportsTokenRequest(req) {
		return nil
	}

	if err := h.checkTokenIssuingPrerequisite(req, resp); err != nil {
		return err
	}

	if oauth.V(req.GetSession().GetGrantedScopes()).Contains(spi.ScopeOpenId) {
		if err := h.IdTokenHelper.GenToken(ctx, req, resp); err != nil {
			return err
		}
	}

	return nil
}

// Return non-nil error when the current request and response object violates the prerequisites required by this handler
// to issue and id token.
func (h *AuthorizeCodeHandler) checkTokenIssuingPrerequisite(req oauth.TokenRequest, resp oauth.Response) error {
	if len(resp.GetString(oauth.AccessToken)) == 0 {
		return spi.ErrServerError(errors.New("access token was not generated"))
	}

	if !IsOidcSession(req.GetSession()) {
		return spi.ErrServerError(errors.New("request must use oidc.Session"))
	}

	return nil
}

func (h *AuthorizeCodeHandler) SupportsTokenRequest(req oauth.TokenRequest) bool {
	return oauth.V(req.GetGrantTypes()).ContainsExactly(spi.GrantTypeCode)
}
