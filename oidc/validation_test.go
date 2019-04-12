package oidc

import (
	"context"
	"fmt"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuthorizeRequestValidator_Validate(t *testing.T) {
	validator := &AuthorizeRequestValidator{
		AuthorizeRequestValidator: &oauth.AuthorizeRequestValidator{
			RequestValidator: &oauth.RequestValidator{},
		},
	}

	for _, v := range []struct {
		name 			string
		reqFunc 		func() AuthorizeRequest
		expectsError	bool
	}{
		{
			name: "invalid response_mode",
			reqFunc: func() AuthorizeRequest {
				req := NewAuthorizeRequest()
				req.SetClient(new(validationTestClient))
				req.AddResponseTypes(spi.ResponseTypeCode)
				req.SetResponseMode("invalid")
				return req
			},
			expectsError: true,
		},
		{
			name: "invalid display",
			reqFunc: func() AuthorizeRequest {
				req := NewAuthorizeRequest()
				req.SetClient(new(validationTestClient))
				req.AddResponseTypes(spi.ResponseTypeCode)
				req.SetDisplay("invalid")
				return req
			},
			expectsError: true,
		},
		{
			name: "invalid prompt",
			reqFunc: func() AuthorizeRequest {
				req := NewAuthorizeRequest()
				req.SetClient(new(validationTestClient))
				req.AddResponseTypes(spi.ResponseTypeCode)
				req.AddPrompt("invalid")
				return req
			},
			expectsError: true,
		},
		{
			name: "none prompt with others",
			reqFunc: func() AuthorizeRequest {
				req := NewAuthorizeRequest()
				req.SetClient(new(validationTestClient))
				req.AddResponseTypes(spi.ResponseTypeCode)
				req.AddPrompt(spi.PromptNone, spi.PromptLogin)
				return req
			},
			expectsError: true,
		},
	}{
		err := validator.Validate(context.Background(), v.reqFunc())
		if v.expectsError {
			assert.NotNil(t, err, v.name)
			fmt.Println(err.(*spi.OAuthError).Reason)
		} else {
			assert.Nil(t, err, v.name)
		}
	}
}

type validationTestClient struct {
	*panicClient
}

func (c *validationTestClient) GetResponseTypes() []string {
	return []string{spi.ResponseTypeCode}
}

func (c *validationTestClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeCode}
}