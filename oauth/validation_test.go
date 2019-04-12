package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/assert"
	"testing"
)

type validatorTest struct {
	name         string
	reqFunc      func() Request
	expectsError bool
}

func TestTokenRequestValidator_Validate(t *testing.T) {
	validator := &TokenRequestValidator{
		RequestValidator: &RequestValidator{},
	}

	for _, v := range []validatorTest{
		{
			name: "no grant types",
			reqFunc: func() Request {
				r := NewTokenRequest()
				r.SetClient(new(validatorTestClient))
				return r
			},
			expectsError: true,
		},
		{
			name: "unsupported grant type",
			reqFunc: func() Request {
				r := NewTokenRequest()
				r.SetClient(new(validatorTestClient))
				r.AddGrantTypes(spi.GrantTypeClient)
				return r
			},
			expectsError: true,
		},
		{
			name: "missing code on grant_type=authorization_code",
			reqFunc: func() Request {
				r := NewTokenRequest()
				r.SetClient(new(validatorTestClient))
				r.AddGrantTypes(spi.GrantTypeCode)
				return r
			},
			expectsError: true,
		},
		{
			name: "missing refresh token on grant_type=refresh_token",
			reqFunc: func() Request {
				r := NewTokenRequest()
				r.SetClient(new(validatorTestClient))
				r.AddGrantTypes(spi.GrantTypeRefresh)
				return r
			},
			expectsError: true,
		},
		{
			name: "pass validation",
			reqFunc: func() Request {
				r := NewTokenRequest()
				r.SetClient(new(validatorTestClient))
				r.AddGrantTypes(spi.GrantTypeCode)
				r.SetCode("some-code")
				return r
			},
			expectsError: false,
		},
	} {
		err := validator.Validate(context.Background(), v.reqFunc())
		if v.expectsError {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestAuthorizeRequestValidator_Validate(t *testing.T) {
	validator := &AuthorizeRequestValidator{
		RequestValidator: &RequestValidator{},
	}

	for _, v := range []validatorTest{
		{
			name: "no response types",
			reqFunc: func() Request {
				r := NewAuthorizeRequest()
				r.SetClient(new(validatorTestClient))
				return r
			},
			expectsError: true,
		},
		{
			name: "unsupported response type",
			reqFunc: func() Request {
				r := NewAuthorizeRequest()
				r.SetClient(new(validatorTestClient))
				r.AddResponseTypes(spi.ResponseTypeIdToken)
				return r
			},
			expectsError: true,
		},
	} {
		err := validator.Validate(context.Background(), v.reqFunc())
		if v.expectsError {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestRequestValidator_Validate(t *testing.T) {
	validator := &RequestValidator{}

	for _, v := range []validatorTest{
		{
			name: "client not set",
			reqFunc: NewRequest,
			expectsError: true,
		},
	} {
		err := validator.Validate(context.Background(), v.reqFunc())
		if v.expectsError {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

type validatorTestClient struct {
	*panicClient
}

func (v *validatorTestClient) GetResponseTypes() []string {
	return []string{spi.ResponseTypeCode}
}

func (v *validatorTestClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeCode, spi.GrantTypeRefresh}
}
