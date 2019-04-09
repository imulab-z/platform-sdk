package oauth

type TokenRequest interface {
	Request
	// Get the grant types
	GetGrantTypes() []string
	// add grant types to the request
	AddGrantTypes(grantTypes ...string)
	// Get the supplied authorization code
	GetCode() string
	// set the authorize code
	SetCode(code string)
	// Get the supplied refresh token
	GetRefreshToken() string
	// set the refresh token
	SetRefreshToken(token string)
}

func NewTokenRequest() TokenRequest {
	return &oauthTokenRequest{
		oauthRequest: NewRequest().(*oauthRequest),
		GrantTypes: make([]string, 0),
		Code: "",
		RefreshToken: "",
	}
}

type oauthTokenRequest struct {
	*oauthRequest
	GrantTypes		[]string 	`json:"grant_types"`
	Code 			string		`json:"code"`
	RefreshToken	string		`json:"refresh_token"`
}

func (r *oauthTokenRequest) GetGrantTypes() []string {
	return r.GrantTypes
}

func (r *oauthTokenRequest) AddGrantTypes(grantTypes ...string) {
	r.GrantTypes = append(r.GrantTypes, grantTypes...)
}

func (r *oauthTokenRequest) GetCode() string {
	return r.Code
}

func (r *oauthTokenRequest) SetCode(code string) {
	r.Code = code
}

func (r *oauthTokenRequest) GetRefreshToken() string {
	return r.RefreshToken
}

func (r *oauthTokenRequest) SetRefreshToken(token string) {
	r.RefreshToken = token
}


