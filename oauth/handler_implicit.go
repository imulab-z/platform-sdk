package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
)

type ImplicitHandler struct {
	AccessTokenHelper 	*AccessTokenHelper
}

func (h *ImplicitHandler) Authorize(ctx context.Context, req AuthorizeRequest, resp Response) error {
	if !h.SupportsAuthorizeRequest(req) {
		return nil
	}

	if !ClientRegisteredGrantType(req.GetClient(), spi.GrantTypeImplicit) {
		return spi.ErrInvalidGrant("client is incapable of implicit grant.")
	}

	if err := h.AccessTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	req.HandledResponseType(spi.ResponseTypeToken)

	return nil
}

func (h *ImplicitHandler) SupportsAuthorizeRequest(req AuthorizeRequest) bool {
	return V(req.GetResponseTypes()).ContainsExactly(spi.ResponseTypeToken)
}

