package oauth

type TokenResponse interface {
	// Returns the assigned access token
	GetAccessToken() string
	// Sets the assigned access token
	SetAccessToken(token string)
	// Returns the type of the token
	GetTokenType() string
	// Sets the type of the token
	SetTokenType(tokenType string)
	// Returns the expires_in parameter
	GetExpiresIn() int64
	// Sets the expires_in parameter
	SetExpiresIn(ttl int64)
	// Returns the assigned refresh token
	GetRefreshToken() string
	// Sets the assigned refresh token
	SetRefreshToken(token string)
}

func NewTokenResponse() TokenResponse {
	return &tokenResponse{
		AccessToken: "",
		TokenType: "Bearer",
		ExpiresIn: 0,
		RefreshToken: "",
	}
}

type tokenResponse struct {
	AccessToken		string
	TokenType 		string
	ExpiresIn 		int64
	RefreshToken	string
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