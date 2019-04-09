package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

var (
	_ oauth.AuthorizeHandler = (*AuthorizeCodeHandler)(nil)
)

type AuthorizeCodeHandler struct {
	*oauth.AuthorizeCodeHandler
	IdTokenHelper	*IdTokenHelper
}

func (h *AuthorizeCodeHandler) Authorize(ctx context.Context, req oauth.AuthorizeRequest, resp oauth.AuthorizeResponse) error {
	if !h.supportsAuthorizeRequest(req) {
		return nil
	}

	// delegate all the work here assuming the AuthorizeCodeRepository#Save implementation
	// saves the oidc session as well.
	return h.AuthorizeCodeHandler.Authorize(ctx, req, resp)
}

func (h *AuthorizeCodeHandler) supportsAuthorizeRequest(req oauth.AuthorizeRequest) bool {
	return isOidcSession(req.GetSession()) &&
		len(req.GetResponseTypes()) == 1 &&
		funk.ContainsString(req.GetResponseTypes(), spi.ResponseTypeCode)
}

func (h *AuthorizeCodeHandler) UpdateSession(ctx context.Context, req oauth.TokenRequest) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}
	return h.AuthorizeCodeHandler.UpdateSession(ctx, req)
}

func (h *AuthorizeCodeHandler) IssueToken(ctx context.Context, req oauth.TokenRequest, resp oauth.TokenResponse) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}

	if !isOidcTokenResponse(resp) {
		panic("this handler must be supplied an oidc.TokenResponse")
	}

	// delegate majority of work to authorize code handler
	if err := h.AuthorizeCodeHandler.IssueToken(ctx, req, resp); err != nil {
		return err
	}

	if !funk.ContainsString(req.GetSession().GetGrantedScopes(), spi.ScopeOpenId) {
		return spi.ErrInvalidGrant("scope openid was not granted.")
	}

	if err := h.IdTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	return nil
}

func (h *AuthorizeCodeHandler) supportsTokenRequest(req TokenRequest) bool {
	return isOidcSession(req.GetSession()) &&
		oauth.Exactly(req.GetGrantTypes(), spi.GrantTypeCode)
}