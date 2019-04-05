package oauth

type AuthorizeResponse interface {
	// Returns the assigned authorization code
	GetCode() string
	// Assign the authorization code
	SetCode(code string)
	// Returns the confirmed redirection uri
	GetRedirectUri() string
	// Set the confirmed redirection uri
	SetRedirectUri(uri string)
}

func NewAuthorizeResponse() AuthorizeResponse {
	return &authorizeResponse{
		Code: "",
		RedirectUri: "",
	}
}

type authorizeResponse struct {
	Code 			string
	RedirectUri		string
}

func (r *authorizeResponse) GetCode() string {
	return r.Code
}

func (r *authorizeResponse) SetCode(code string) {
	r.Code = code
}

func (r *authorizeResponse) GetRedirectUri() string {
	return r.RedirectUri
}

func (r *authorizeResponse) SetRedirectUri(uri string) {
	r.RedirectUri = uri
}



