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
}

func (v *AuthorizeRequestValidator) Validate(ctx context.Context, req Request) error {
	authReq := req.(AuthorizeRequest)

	if err := v.RequestValidator.Validate(ctx, authReq); err != nil {
		return err
	}

	if len(authReq.GetResponseTypes()) == 0 {
		return spi.ErrInvalidRequest("at least one response_type is required")
	}

	for _, aResponseType := range authReq.GetResponseTypes() {
		if !ClientRegisteredResponseType(req.GetClient(), aResponseType) {
			return spi.ErrInvalidRequest(fmt.Sprintf("client does not support response_type %s", aResponseType))
		}
	}

	return nil
}

// Validator for TokenRequest
type TokenRequestValidator struct {
	*RequestValidator
}

func (v *TokenRequestValidator) Validate(ctx context.Context, req Request) error {
	tokenReq := req.(TokenRequest)

	if err := v.RequestValidator.Validate(ctx, tokenReq); err != nil {
		return err
	}

	if len(tokenReq.GetGrantTypes()) == 0 {
		return spi.ErrInvalidRequest("at least one grant_type is required")
	}

	for _, aGrantType := range tokenReq.GetGrantTypes() {
		if !ClientRegisteredGrantType(tokenReq.GetClient(), aGrantType) {
			return spi.ErrInvalidRequest(fmt.Sprintf("client does not support grant_type %s", aGrantType))
		}
	}

	if V(tokenReq.GetGrantTypes()).Contains(spi.GrantTypeCode) {
		if len(tokenReq.GetCode()) == 0 {
			return spi.ErrInvalidRequest("authorization code is missing")
		}
	}

	if V(tokenReq.GetGrantTypes()).Contains(spi.GrantTypeRefresh) {
		if len(tokenReq.GetRefreshToken()) == 0 {
			return spi.ErrInvalidRequest("refresh token is missing")
		}
	}

	return nil
}



