package oidc

import "github.com/imulab-z/platform-sdk/oauth"

type TokenRequest interface {
	oauth.TokenRequest
}

func NewTokenRequest() TokenRequest {
	return nil
}

type tokenRequest struct {
	oauth.TokenRequest
}
