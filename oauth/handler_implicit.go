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

	if !funk.ContainsString(req.GetClient().GetGrantTypes(), spi.GrantTypeImplicit) {
		return spi.ErrInvalidGrant("client is incapable of implicit grant.")
	}

	if err := h.AccessTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	resp.Set(RedirectUri, req.GetRedirectUri())

	req.HandledResponseType(spi.ResponseTypeToken)

	return nil
}

func (h *ImplicitHandler) supportsAuthorizeRequest(req AuthorizeRequest) bool {
	return Exactly(req.GetResponseTypes(), spi.ResponseTypeToken)
}

