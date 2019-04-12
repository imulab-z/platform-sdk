package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
)

var (
	_ oauth.Validator = (*AuthorizeRequestValidator)(nil)
	_ oauth.Validator = (*TokenRequestValidator)(nil)
)

type AuthorizeRequestValidator struct {
	*oauth.AuthorizeRequestValidator
	ResponseModesOverride []string
	DisplayValuesOverride []string
}

func (v *AuthorizeRequestValidator) Validate(ctx context.Context, req oauth.Request) error {
	authReq := req.(AuthorizeRequest)

	if err := v.AuthorizeRequestValidator.Validate(ctx, authReq); err != nil {
		return err
	}

	if err := v.validateResponseMode(authReq); err != nil {
		return err
	}

	if err := v.validateDisplay(authReq); err != nil {
		return err
	}

	if err := v.validatePrompts(authReq); err != nil {
		return err
	}

	return nil
}

func (v *AuthorizeRequestValidator) validateResponseMode(authReq AuthorizeRequest) error {
	if len(authReq.GetResponseMode()) > 0 {
		if !oauth.V(v.supportedResponseModes()).Contains(authReq.GetResponseMode()) {
			return spi.ErrInvalidRequest("invalid response_mode value")
		}
	}
	return nil
}

func (v *AuthorizeRequestValidator) validateDisplay(authReq AuthorizeRequest) error {
	if len(authReq.GetDisplay()) > 0 {
		if !oauth.V(v.supportedDisplayValues()).Contains(authReq.GetDisplay()) {
			return spi.ErrInvalidRequest("invalid display value")
		}
	}
	return nil
}

func (v *AuthorizeRequestValidator) validatePrompts(authReq AuthorizeRequest) error {
	if len(authReq.GetPrompts()) == 0 {
		return nil
	}

	if !oauth.V([]string{
		spi.PromptNone,
		spi.PromptLogin,
		spi.PromptConsent,
		spi.PromptSelectAccount,
	}).Contains(authReq.GetPrompts()...) {
		return spi.ErrInvalidRequest("invalid prompt value")
	}

	switch {
	case oauth.V(authReq.GetPrompts()).Contains(spi.PromptNone):
		if len(authReq.GetPrompts()) > 1 {
			return spi.ErrInvalidRequest("'none' prompt must be used alone")
		}
	}

	return nil
}

func (v *AuthorizeRequestValidator) supportedResponseModes() []string {
	if len(v.ResponseModesOverride) > 0 {
		return v.ResponseModesOverride
	}
	return []string{
		spi.ResponseModeQuery,
		spi.ResponseModeFragment,
	}
}

func (v *AuthorizeRequestValidator) supportedDisplayValues() []string {
	if len(v.DisplayValuesOverride) > 0 {
		return v.DisplayValuesOverride
	}
	return []string{
		spi.DisplayPage,
		spi.DisplayPopup,
		spi.DisplayTouch,
		spi.DisplayWap,
	}
}

type TokenRequestValidator struct {
	*oauth.TokenRequestValidator
}