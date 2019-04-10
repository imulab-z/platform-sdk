package oauth

const (
	Code         = "code"
	RedirectUri  = "redirect_uri"
	AccessToken  = "access_token"
	TokenType    = "token_type"
	ExpiresIn    = "expires_in"
	RefreshToken = "refresh_token"
)

type Response map[string]interface{}

func NewResponse() Response {
	return make(map[string]interface{})
}

func (r Response) GetString(key string) string {
	if str, ok := r[key].(string); !ok {
		return ""
	} else {
		return str
	}
}

func (r Response) Get(key string) interface{} {
	return r[key]
}

func (r Response) Set(key string, value interface{}) {
	r[key] = value
}