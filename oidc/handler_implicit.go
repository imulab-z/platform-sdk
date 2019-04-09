package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

type ImplicitHandler struct {
	AccessTokenHelper *oauth.AccessTokenHelper
	IdTokenHelper     *IdTokenHelper
}

func (h *ImplicitHandler) Authorize(ctx context.Context, req oauth.AuthorizeRequest, resp oauth.AuthorizeResponse) error {
	if !h.supportsAuthorizeRequest(req) {
		return nil
	}

	// client must be able to use grant_type=implicit
	if !funk.ContainsString(req.GetClient().GetGrantTypes(), spi.GrantTypeImplicit) {
		return spi.ErrInvalidGrant("client is incapable of implicit grant.")
	}

	// issue access token if necessary
	if funk.ContainsString(req.GetResponseTypes(), spi.ResponseTypeToken) {
		if _, ok := resp.GetExtra()["access_token"]; !ok {
			if err := h.AccessTokenHelper.GenToken2(ctx, req, resp); err != nil {
				return err
			}
		}
		req.HandledResponseType(spi.ResponseTypeToken)
	}

	if err := h.IdTokenHelper.GenToken2(ctx, req, resp); err != nil {
		return err
	}

	req.HandledResponseType(spi.ResponseTypeIdToken)
	return nil
}

func (h *ImplicitHandler) supportsAuthorizeRequest(req oauth.AuthorizeRequest) bool {
	return isOidcSession(req.GetSession()) &&
		funk.ContainsString(req.GetSession().GetGrantedScopes(), spi.ScopeOpenId) &&
		(oauth.Exactly(req.GetResponseTypes(), spi.ResponseTypeIdToken) ||
			oauth.Exactly(req.GetResponseTypes(), spi.ResponseTypeToken, spi.ResponseTypeIdToken))
}

