package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

type ImplicitHandler struct {
	AccessTokenHelper 	*AccessTokenHelper
}

func (h *ImplicitHandler) Authorize(ctx context.Context, req AuthorizeRequest, resp Response) error {
	if !h.supportsAuthorizeRequest(req) {
		return nil
	}

	defer req.HandledResponseType(spi.ResponseTypeToken)

	if !funk.ContainsString(req.GetClient().GetGrantTypes(), spi.GrantTypeImplicit) {
		return spi.ErrInvalidGrant("client is incapable of implicit grant.")
	}

	return h.AccessTokenHelper.GenToken(ctx, req, resp)
}

func (h *ImplicitHandler) supportsAuthorizeRequest(req AuthorizeRequest) bool {
	return Exactly(req.GetResponseTypes(), spi.ResponseTypeToken)
}

