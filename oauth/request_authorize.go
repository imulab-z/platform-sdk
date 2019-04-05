package oauth

type AuthorizeRequest interface {
	Request
	// Get requested response types
	GetResponseTypes() []string
	// Add response types
	addResponseTypes(responseTypes ...string)
	// Get requested scopes
	GetScopes() []string
	// Add scopes
	addScopes(scopes ...string)
	// Get the supplied state parameter
	GetState() string
	// Set state
	setState(state string)
	// Set the response type to handled
	HandledResponseType(responseType string)
	// Returns true if the response type has been handled; false otherwise
	IsResponseTypeHandled(responseType string) bool
}

func NewAuthorizeRequest() AuthorizeRequest {
	return &authorizeRequest{
		oauthRequest: NewRequest().(*oauthRequest),
		ResponseTypes: make([]string, 0),
		Scopes: make([]string, 0),
		State: "",
		handleMap: make(map[string]struct{}),
	}
}

type authorizeRequest struct {
	*oauthRequest
	ResponseTypes []string				`json:"response_types"`
	Scopes        []string				`json:"scopes"`
	State         string				`json:"state"`
	handleMap     map[string]struct{}	`json:"-"`
}

func (r *authorizeRequest) GetResponseTypes() []string {
	return r.ResponseTypes
}

func (r *authorizeRequest) addResponseTypes(responseTypes ...string) {
	r.ResponseTypes = append(r.ResponseTypes, responseTypes...)
}

func (r *authorizeRequest) GetScopes() []string {
	return r.Scopes
}

func (r *authorizeRequest) addScopes(scopes ...string) {
	r.Scopes = append(r.Scopes, scopes...)
}

func (r *authorizeRequest) GetState() string {
	return r.State
}

func (r *authorizeRequest) setState(state string) {
	r.State = state
}

func (r *authorizeRequest) HandledResponseType(responseType string) {
	r.handleMap[responseType] = struct{}{}
}

func (r *authorizeRequest) IsResponseTypeHandled(responseType string) bool {
	_, ok := r.handleMap[responseType]
	return ok
}


