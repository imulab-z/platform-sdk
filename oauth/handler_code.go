package oauth

import (
	"context"
	"fmt"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

type AuthorizeCodeHandler struct {
	ScopeComparator    Comparator
	CodeStrategy       AuthorizeCodeStrategy
	CodeRepo           AuthorizeCodeRepository
	AccessTokenHelper  *AccessTokenHelper
	RefreshTokenHelper *RefreshTokenHelper
}

func (h *AuthorizeCodeHandler) Authorize(ctx context.Context, req AuthorizeRequest, resp Response) error {
	var (
		code string
		err  error
	)

	if !h.supportsAuthorizeRequest(req) {
		return nil
	}

	err = h.checkAuthorizePrerequisite(req)
	if err != nil {
		return err
	}

	code, err = h.issueCode(ctx, req)
	if err != nil {
		return err
	}

	resp.Set(Code, code)

	req.HandledResponseType(spi.ResponseTypeCode)

	return nil
}

// Returns nil if the given request is fit to be authorized; returns an error otherwise.
// A request can be authorized if the requesting client registered 'code' as response_type and accepts all of the
// granted scopes in the request session.
func (h *AuthorizeCodeHandler) checkAuthorizePrerequisite(req AuthorizeRequest) error {
	if !ClientRegisteredResponseType(req.GetClient(), spi.ResponseTypeCode) {
		return spi.ErrUnauthorizedClient(fmt.Sprintf("client disabled response_type=%s", spi.ResponseTypeCode))
	}

	if !ClientAcceptsGrantedScopes(req, h.ScopeComparator) {
		return ErrClientRejectScope
	}

	return nil
}

// Returns the newly generated and saved authorization code if no error; otherwise returns empty string and the error.
func (h *AuthorizeCodeHandler) issueCode(ctx context.Context, req AuthorizeRequest) (string, error) {
	if code, err := h.CodeStrategy.NewCode(ctx, req); err != nil {
		return "", err
	} else if err := h.CodeRepo.Save(ctx, code, req); err != nil {
		return "", err
	} else {
		return code, nil
	}
}

func (h *AuthorizeCodeHandler) supportsAuthorizeRequest(req AuthorizeRequest) bool {
	return V(req.GetResponseTypes()).Contains(spi.ResponseTypeCode)
}

func (h *AuthorizeCodeHandler) UpdateSession(ctx context.Context, req TokenRequest) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}

	// for security purposes, the requested code shall be deleted after a single use, either by
	// the authorized client or by a malicious party.
	defer func() {
		go h.CodeRepo.Delete(context.Background(), req.GetCode())
	}()

	if oldReq, err := h.reviveCode(ctx, req); err != nil {
		return err
	} else {
		req.GetSession().SetLastRequestId(oldReq.GetId())
		req.GetSession().Merge(oldReq.GetSession())
	}

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

// Returns the issuing authorization request associated with the given authorization code, if any; otherwise, returns
// a non-nil error when code is malformed, missing or is being illegally used.
func (h *AuthorizeCodeHandler) reviveCode(ctx context.Context, req TokenRequest) (Request, error) {
	var (
		oldReq 	AuthorizeRequest
		err 	error
	)

	if !ClientRegisteredGrantType(req.GetClient(), spi.GrantTypeCode) {
		return nil, spi.ErrInvalidGrant("client unable to use authorization_code grant type.")
	}

	oldReq, err = h.CodeRepo.GetRequest(ctx, req.GetCode())
	if err != nil {
		return nil, err
	}

	err = h.CodeStrategy.ValidateCode(ctx, req.GetCode(), oldReq)
	if err != nil {
		return nil, err
	}

	if req.GetClient().GetId() != oldReq.GetClient().GetId() {
		return nil, spi.ErrUnauthorizedClient("client is not authorized to use this authorization code.")
	}

	if req.GetRedirectUri() != oldReq.GetRedirectUri() {
		// note: code repository must return the effective redirect_uri as req.GetRedirectUri()
		return nil, spi.ErrUnauthorizedClient("authorization code was issued to a different redirect uri.")
	}

	return oldReq, nil
}

func (h *AuthorizeCodeHandler) supportsTokenRequest(req TokenRequest) bool {
	return V(req.GetGrantTypes()).ContainsExactly(spi.GrantTypeCode)
}
