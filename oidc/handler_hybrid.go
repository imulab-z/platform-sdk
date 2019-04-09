package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
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

	// generate access_token if required
	if funk.ContainsString(req.GetResponseTypes(), spi.ResponseTypeToken) {
		if !funk.ContainsString(req.GetClient().GetGrantTypes(), spi.GrantTypeImplicit) {
			return spi.ErrInvalidGrant("client is incapable of implicit grant.")
		}

		if err := h.AccessTokenHelper.GenToken(ctx, req, resp); err != nil {
			return err
		}

		req.HandledResponseType(spi.ResponseTypeToken)
	}

	// generate id_token if required
	if funk.ContainsString(req.GetResponseTypes(), spi.ResponseTypeIdToken) &&
		funk.ContainsString(req.GetSession().GetGrantedScopes(), spi.ScopeOpenId) {

		if err := h.IdTokenHelper.GenToken(ctx, req, resp); err != nil {
			return err
		}

		req.HandledResponseType(spi.ResponseTypeIdToken)
	}

	return nil
}

func (h *HybridHandler) supportsAuthorizeRequest(req oauth.AuthorizeRequest) bool {
	switch len(req.GetResponseTypes()) {
	case 2:
		return oauth.Exactly(req.GetResponseTypes(), spi.ResponseTypeCode, spi.ResponseTypeToken) ||
			oauth.Exactly(req.GetResponseTypes(), spi.ResponseTypeCode, spi.ResponseTypeIdToken)
	case 3:
		return oauth.Exactly(req.GetResponseTypes(), spi.ResponseTypeCode, spi.ResponseTypeToken, spi.ResponseTypeIdToken)
	default:
		return false
	}
}

func (h *HybridHandler) UpdateSession(ctx context.Context, req oauth.TokenRequest) error {
	return h.AuthorizeCodeHandler.UpdateSession(ctx, req)
}

func (h *HybridHandler) IssueToken(ctx context.Context, req oauth.TokenRequest, resp oauth.Response) error {
	return h.AuthorizeCodeHandler.IssueToken(ctx, req, resp)
}
