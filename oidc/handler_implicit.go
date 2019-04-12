package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
)

var (
	_ oauth.AuthorizeHandler = (*ImplicitHandler)(nil)
)

type ImplicitHandler struct {
	AccessTokenHelper *oauth.AccessTokenHelper
	IdTokenHelper     *IdTokenHelper
}

func (h *ImplicitHandler) Authorize(ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error {
	if !h.SupportsAuthorizeRequest(req) {
		return nil
	}

	if err := h.checkAuthorizePrerequisite(req); err != nil {
		return err
	}

	if err := h.issueAccessTokenIfRequired(ctx, req, resp); err != nil {
		return err
	}

	if err := h.issueIdToken(ctx, req, resp); err != nil {
		return err
	}

	return nil
}

func (h *ImplicitHandler) issueAccessTokenIfRequired(
	ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error {
	if len(resp.GetString(oauth.AccessToken)) > 0 {
		return nil
	} else if !oauth.V(req.GetResponseTypes()).Contains(spi.ResponseTypeToken) {
		return nil
	}

	if !oauth.ClientRegisteredResponseType(req.GetClient(), spi.ResponseTypeToken) {
		return spi.ErrInvalidGrant("client is incapable of using token response type.")
	}

	if err := h.AccessTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	req.HandledResponseType(spi.ResponseTypeToken)

	return nil
}

func (h *ImplicitHandler) issueIdToken(
	ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error {
	if !oauth.ClientRegisteredResponseType(req.GetClient(), spi.ResponseTypeIdToken) {
		return spi.ErrInvalidGrant("client is incapable of using id_token response type.")
	}

	if err := h.IdTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	req.HandledResponseType(spi.ResponseTypeIdToken)

	return nil
}

func (h *ImplicitHandler) checkAuthorizePrerequisite(req oauth.AuthorizeRequest) error {
	if !oauth.ClientRegisteredGrantType(req.GetClient(), spi.GrantTypeImplicit) {
		return spi.ErrInvalidGrant("client is incapable of implicit grant.")
	}

	return nil
}

func (h *ImplicitHandler) SupportsAuthorizeRequest(req oauth.AuthorizeRequest) bool {
	v := oauth.V(req.GetResponseTypes())
	switch {
	case v.ContainsExactly(spi.ResponseTypeIdToken),
		v.ContainsExactly(spi.ResponseTypeToken, spi.ResponseTypeIdToken):
		return oauth.V(req.GetSession().GetGrantedScopes()).Contains(spi.ScopeOpenId)
	default:
		return false
	}
}
