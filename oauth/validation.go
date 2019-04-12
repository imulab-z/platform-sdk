package oauth

import (
	"context"
	"fmt"
	"github.com/imulab-z/platform-sdk/spi"
)

type Validator interface {
	Validate(ctx context.Context, req Request) error
}

// Validator shared for the base Request
type RequestValidator struct {}

func (v *RequestValidator) Validate(ctx context.Context, req Request) error {
	if req.GetClient() == nil {
		return spi.ErrServerErrorf("client is required")
	}

	if req.GetSession() == nil {
		return spi.ErrServerErrorf("session is required")
	}

	return nil
}

// Validator for AuthorizeRequest
type AuthorizeRequestValidator struct {
	*RequestValidator
	ResponseTypesOverride	[]string
}

func (v *AuthorizeRequestValidator) Validate(ctx context.Context, req Request) error {
	authReq := req.(AuthorizeRequest)

	if err := v.RequestValidator.Validate(ctx, authReq); err != nil {
		return err
	}

	if err := v.validateResponseTypes(authReq); err != nil {
		return err
	}

	return nil
}

func (v *AuthorizeRequestValidator) validateResponseTypes(req AuthorizeRequest) error {
	if len(req.GetResponseTypes()) == 0 {
		return spi.ErrInvalidRequest("at least one response_type is required")
	}

	if !V(v.supportedResponseTypes()).Contains(req.GetResponseTypes()...) {
		return spi.ErrInvalidRequest("unsupported response_type")
	}

	for _, aResponseType := range req.GetResponseTypes() {
		if !ClientRegisteredResponseType(req.GetClient(), aResponseType) {
			return spi.ErrInvalidRequest(fmt.Sprintf("client does not support response_type %s", aResponseType))
		}
	}

	return nil
}

func (v *AuthorizeRequestValidator) supportedResponseTypes() []string {
	if len(v.ResponseTypesOverride) > 0 {
		return v.ResponseTypesOverride
	}
	return []string{
		spi.ResponseTypeCode,
		spi.ResponseTypeToken,
		// this slightly breaks SOLID principle by reaching out to OIDC space, but it makes
		// our lives so much easier and it's only a constant, so we will just live with it.
		spi.ResponseTypeIdToken,
	}
}

// Validator for TokenRequest
type TokenRequestValidator struct {
	*RequestValidator
	GrantTypesOverride []string
}

func (v *TokenRequestValidator) Validate(ctx context.Context, req Request) error {
	tokenReq := req.(TokenRequest)

	if err := v.RequestValidator.Validate(ctx, tokenReq); err != nil {
		return err
	}

	if err := v.validateGrantType(tokenReq); err != nil {
		return err
	}

	if err := v.validateAuthorizationCode(tokenReq); err != nil {
		return err
	}

	if err := v.validateRefreshToken(tokenReq); err != nil {
		return err
	}

	return nil
}

func (v *TokenRequestValidator) validateGrantType(req TokenRequest) error {
	if len(req.GetGrantTypes()) == 0 {
		return spi.ErrInvalidRequest("at least one grant_type is required")
	}

	if !V(v.supportedGrantTypes()).Contains(req.GetGrantTypes()...) {
		return spi.ErrInvalidRequest("unsupported grant_type")
	}

	for _, aGrantType := range req.GetGrantTypes() {
		if !ClientRegisteredGrantType(req.GetClient(), aGrantType) {
			return spi.ErrInvalidRequest(fmt.Sprintf("client does not support grant_type %s", aGrantType))
		}
	}

	return nil
}

func (v *TokenRequestValidator) validateAuthorizationCode(req TokenRequest) error {
	if !V(req.GetGrantTypes()).Contains(spi.GrantTypeCode) {
		return nil
	}

	if len(req.GetCode()) == 0 {
		return spi.ErrInvalidRequest("authorization code is missing")
	}

	return nil
}

func (v *TokenRequestValidator) validateRefreshToken(req TokenRequest) error {
	if !V(req.GetGrantTypes()).Contains(spi.GrantTypeRefresh) {
		return nil
	}

	if len(req.GetRefreshToken()) == 0 {
		return spi.ErrInvalidRequest("refresh token is missing")
	}

	return nil
}

func (v *TokenRequestValidator) supportedGrantTypes() []string {
	if len(v.GrantTypesOverride) > 0 {
		return v.GrantTypesOverride
	}
	return []string{
		spi.GrantTypeCode,
		spi.GrantTypeImplicit,
		spi.GrantTypeClient,
		spi.GrantTypeRefresh,
		// there is no plan to support password grant_type for now, hence not included
	}
}



