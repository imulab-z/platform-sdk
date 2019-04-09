package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

// Supplement handler for dealing with the Open ID Connect protocol side of the refresh flow.
// This handler needs to be used in combination and after the oauth.RefreshHandler.
type RefreshHandler struct {
	IdTokenHelper 	*IdTokenHelper
}

func (h *RefreshHandler) UpdateSession(ctx context.Context, req oauth.TokenRequest) error {
	return nil
}

func (h *RefreshHandler) IssueToken(ctx context.Context, req oauth.TokenRequest, resp oauth.Response) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}

	return h.IdTokenHelper.GenToken(ctx, req, resp)
}

func (h *RefreshHandler) supportsTokenRequest(req oauth.TokenRequest) bool {
	return funk.ContainsString(req.GetGrantTypes(), spi.GrantTypeRefresh) &&
		funk.ContainsString(req.GetSession().GetGrantedScopes(), spi.ScopeOpenId)
}

