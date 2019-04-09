package oauth

import (
	"context"
	"fmt"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

type AuthorizeCodeHandler struct {
	ScopeStrategy 		ScopeStrategy
	CodeStrategy  		AuthorizeCodeStrategy
	CodeRepo      		AuthorizeCodeRepository
	AccessTokenHelper	*AccessTokenHelper
	RefreshTokenHelper	*RefreshTokenHelper
}

func (h *AuthorizeCodeHandler) Authorize(ctx context.Context, req AuthorizeRequest, resp Response) error {
	if !h.supportsAuthorizeRequest(req) {
		return nil
	}

	defer req.HandledResponseType(spi.ResponseTypeCode)

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
		resp.Set(RParamCode, code)
	}

	if len(req.GetRedirectUri()) == 0 {
		resp.Set(RParamRedirectUri, req.GetClient().GetRedirectUris()[0])
	} else {
		resp.Set(RParamRedirectUri, req.GetRedirectUri())
	}

	return nil
}

func (h *AuthorizeCodeHandler) supportsAuthorizeRequest(req AuthorizeRequest) bool {
	return funk.ContainsString(req.GetResponseTypes(), spi.ResponseTypeCode)
}

func (h *AuthorizeCodeHandler) UpdateSession(ctx context.Context, req TokenRequest) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}

	authorizeReq, err := h.CodeRepo.GetRequest(ctx, req.GetCode())
	if err != nil {
		return err
	} else if err := h.CodeStrategy.ValidateCode(ctx, req.GetCode(), authorizeReq); err != nil {
		return err
	}

	// this code exists and should be invalidated after a single use no matter what the condition is for security.
	// in most cases, not blocking the call will not cause an issue.
	defer func() {
		go h.CodeRepo.Delete(context.Background(), req.GetCode())
	}()

	if req.GetClient().GetId() != authorizeReq.GetClient().GetId() {
		return spi.ErrUnauthorizedClient("client is not authorized to use this authorization code.")
	} else if req.GetRedirectUri() != authorizeReq.GetRedirectUri() {
		// note: code repository must return the effective redirect_uri as req.GetRedirectUri()
		return spi.ErrUnauthorizedClient("authorization code was issued to a different redirect uri.")
	}

	req.GetSession().Merge(authorizeReq.GetSession())

	return nil
}

func (h *AuthorizeCodeHandler) IssueToken(ctx context.Context, req TokenRequest, resp Response) error {
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

	return nil
}

func (h *AuthorizeCodeHandler) supportsTokenRequest(req TokenRequest) bool {
	return Exactly(req.GetGrantTypes(), spi.GrantTypeCode)
}
