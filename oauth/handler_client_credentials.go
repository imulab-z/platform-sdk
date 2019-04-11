package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

type ClientCredentialsHandler struct {
	AccessTokenHelper 	*AccessTokenHelper
	RefreshTokenHelper 	*RefreshTokenHelper
	ScopeStrategy 		ScopeStrategy
}

func (h *ClientCredentialsHandler) UpdateSession(ctx context.Context, req TokenRequest) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}

	if req.GetClient().GetType() == spi.ClientTypePublic {
		return spi.ErrInvalidClient("public client cannot use client_credentials flow.", "")
	} else if !funk.ContainsString(req.GetClient().GetGrantTypes(), spi.GrantTypeClient) {
		return spi.ErrInvalidGrant("client unable to use client_credentials grant.")
	}

	if !h.ScopeStrategy.AcceptsAll(req.GetClient(), req.GetScopes()) {
		return spi.ErrInvalidScope("scope is not accepted by client.")
	}

	// automatically grant all registered scopes
	req.GetSession().AddGrantedScopes(req.GetScopes()...)

	return nil
}

func (h *ClientCredentialsHandler) IssueToken(ctx context.Context, req TokenRequest, resp Response) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}

	if err := h.AccessTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	if funk.ContainsString(req.GetSession().GetGrantedScopes(), spi.ScopeOfflineAccess) {
		if err := h.RefreshTokenHelper.GenToken(ctx, req, resp); err != nil {
			return err
		}
	}

	resp.Set(RedirectUri, req.GetRedirectUri())

	return nil
}

func (h *ClientCredentialsHandler) supportsTokenRequest(req TokenRequest) bool {
	return Exactly(req.GetGrantTypes(), spi.GrantTypeClient)
}
