package oidc

import "github.com/imulab-z/platform-sdk/oauth"

type TokenResponse interface {
	oauth.TokenResponse
	GetIdToken() string
	SetIdToken(token string)
}

func NewTokenResponse() TokenResponse {
	return &tokenResponse{
		AccessToken: "",
		TokenType: "",
		ExpiresIn: 0,
		IdToken: "",
		RefreshToken: "",
	}
}

type tokenResponse struct {
	AccessToken		string
	TokenType 		string
	ExpiresIn 		int64
	RefreshToken	string
	IdToken			string
}

func (r *tokenResponse) GetIdToken() string {
	return r.IdToken
}

func (r *tokenResponse) SetIdToken(token string) {
	r.IdToken = token
}

func (r *tokenResponse) GetAccessToken() string {
	return r.AccessToken
}

func (r *tokenResponse) SetAccessToken(token string) {
	r.AccessToken = token
}

func (r *tokenResponse) GetTokenType() string {
	return r.TokenType
}

func (r *tokenResponse) SetTokenType(tokenType string) {
	r.TokenType = tokenType
}

func (r *tokenResponse) GetExpiresIn() int64 {
	return r.ExpiresIn
}

func (r *tokenResponse) SetExpiresIn(ttl int64) {
	r.ExpiresIn = ttl
}

func (r *tokenResponse) GetRefreshToken() string {
	return r.RefreshToken
}

func (r *tokenResponse) SetRefreshToken(token string) {
	r.RefreshToken = token
}

func isOidcTokenResponse(resp oauth.TokenResponse) bool {
	_, ok := resp.(TokenResponse)
	return ok
}