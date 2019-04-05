package oauth

import (
	"context"
	"fmt"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

type AuthorizeCodeHandler struct {
	ScopeStrategy ScopeStrategy
	CodeStrategy  AuthorizeCodeStrategy
	CodeRepo      AuthorizeCodeRepository
	Next          AuthorizeHandler
}

func (h *AuthorizeCodeHandler) Handle(ctx context.Context, req AuthorizeRequest, resp AuthorizeResponse) error {
	if !h.supported(req) {
		goto next
	}

	if !funk.ContainsString(req.GetClient().GetResponseTypes(), spi.ResponseTypeCode) {
		return spi.ErrUnauthorizedClient(fmt.Sprintf("client disabled response_type=%s", spi.ResponseTypeCode))
	} else if !funk.ContainsString(req.GetClient().GetGrantTypes(), spi.GrantTypeCode) {
		return spi.ErrUnauthorizedClient(fmt.Sprintf("client disabled grant_type=%s", spi.GrantTypeCode))
	}

	if !h.ScopeStrategy.AcceptsAll(req.GetClient(), req.GetSession().GetGrantedScopes()) {
		return ErrClientRejectScope
	}

	if code, err := h.CodeStrategy.NewCode(ctx, req); err != nil {
		return err
	} else if err := h.CodeRepo.Save(ctx, code, req); err != nil {
		return err
	} else {
		resp.SetCode(code)
	}

	if len(req.GetRedirectUri()) == 0 {
		resp.SetRedirectUri(req.GetClient().GetRedirectUris()[0])
	} else {
		resp.SetRedirectUri(req.GetRedirectUri())
	}

next:
	if h.Next != nil {
		return h.Next.Handle(ctx, req, resp)
	}
	return nil
}

func (h *AuthorizeCodeHandler) supported(req AuthorizeRequest) bool {
	return funk.ContainsString(req.GetResponseTypes(), spi.ResponseTypeCode)
}
