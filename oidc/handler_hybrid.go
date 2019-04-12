package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
)

var (
	_ oauth.AuthorizeHandler = (*HybridHandler)(nil)
	_ oauth.TokenHandler = (*HybridHandler)(nil)
)

type HybridHandler struct {
	*AuthorizeCodeHandler
	AccessTokenHelper *oauth.AccessTokenHelper
	IdTokenHelper     *IdTokenHelper
}

func (h *HybridHandler) Authorize(ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error {
	// delegate to oidc.AuthorizeCodeHandler to generate authorization_code
	if err := h.AuthorizeCodeHandler.Authorize(ctx, req, resp); err != nil {
		return err
	}

	if err := h.issueAccessTokenIfRequired(ctx, req, resp); err != nil {
		return err
	}

	if err := h.issueIdTokenIfRequired(ctx, req, resp); err != nil {
		return err
	}

	return nil
}

// This method issues an access token if the requested response type contains 'token' and client has registered 'implicit'
// as its grant type. If token creation failed, an non-nil error is returned.
func (h *HybridHandler) issueAccessTokenIfRequired(
	ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error {
	if !oauth.V(req.GetResponseTypes()).Contains(spi.ResponseTypeToken) {
		return nil
	}

	if !oauth.ClientRegisteredResponseType(req.GetClient(), spi.ResponseTypeToken) {
		return spi.ErrInvalidGrant("client is incapable of using token response type.")
	}

	if !oauth.ClientRegisteredGrantType(req.GetClient(), spi.GrantTypeImplicit) {
		return spi.ErrInvalidGrant("client is incapable of implicit grant.")
	}

	if err := h.AccessTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	req.HandledResponseType(spi.ResponseTypeToken)

	return nil
}

// This method issues an id token if request response type contains 'id_token' and scope 'openid' is granted by user.
// If the issuing process failed, a non-nil error is returned.
func (h *HybridHandler) issueIdTokenIfRequired(
	ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error  {
	if !oauth.V(req.GetResponseTypes()).Contains(spi.ResponseTypeIdToken) {
		return nil
	} else if !oauth.V(req.GetSession().GetGrantedScopes()).Contains(spi.ScopeOpenId) {
		return nil
	}

	if !oauth.ClientRegisteredResponseType(req.GetClient(), spi.ResponseTypeIdToken) {
		return spi.ErrInvalidGrant("client is incapable of using id_token response type.")
	}

	if err := h.IdTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	req.HandledResponseType(spi.ResponseTypeIdToken)

	return nil
}

func (h *HybridHandler) SupportsAuthorizeRequest(req oauth.AuthorizeRequest) bool {
	v := oauth.V(req.GetResponseTypes())
	switch {
	case v.ContainsExactly(spi.ResponseTypeCode, spi.ResponseTypeToken),
		v.ContainsExactly(spi.ResponseTypeCode, spi.ResponseTypeIdToken),
		v.ContainsExactly(spi.ResponseTypeCode, spi.ResponseTypeToken, spi.ResponseTypeIdToken):
		return true
	default:
		return false
	}
}
