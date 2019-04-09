package oidc

import "github.com/imulab-z/platform-sdk/oauth"

type TokenRequest interface {
	oauth.TokenRequest
}

func NewTokenRequest() TokenRequest {
	return &tokenRequest{
		oidcRequest: NewRequest().(*oidcRequest),
		Code: "",
		RefreshToken: "",
		GrantTypes: make([]string, 0),
	}
}

type tokenRequest struct {
	*oidcRequest
	GrantTypes		[]string 	`json:"grant_types"`
	Code 			string		`json:"code"`
	RefreshToken	string		`json:"refresh_token"`
}

func (r *tokenRequest) AddGrantTypes(grantTypes ...string) {
	r.GrantTypes = append(r.GrantTypes, grantTypes...)
}

func (r *tokenRequest) GetCode() string {
	return r.Code
}

func (r *tokenRequest) GetGrantTypes() []string {
	return r.GrantTypes
}

func (r *tokenRequest) GetRefreshToken() string {
	return r.RefreshToken
}

func (r *tokenRequest) SetCode(code string) {
	r.Code = code
}

func (r *tokenRequest) SetRefreshToken(token string) {
	r.RefreshToken = token
}

