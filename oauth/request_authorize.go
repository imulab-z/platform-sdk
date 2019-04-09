package oauth

type AuthorizeRequest interface {
	Request
	// Get requested response types
	GetResponseTypes() []string
	// Add response types
	AddResponseTypes(responseTypes ...string)
	// Get the supplied state parameter
	GetState() string
	// Set state
	SetState(state string)
	// Set the response type to handled
	HandledResponseType(responseType string)
	// Returns true if the response type has been handled; false otherwise
	IsResponseTypeHandled(responseType string) bool
}

func NewAuthorizeRequest() AuthorizeRequest {
	return &authorizeRequest{
		oauthRequest: NewRequest().(*oauthRequest),
		ResponseTypes: make([]string, 0),
		State: "",
		handleMap: make(map[string]struct{}),
	}
}

type authorizeRequest struct {
	*oauthRequest
	ResponseTypes []string				`json:"response_types"`
	State         string				`json:"state"`
	handleMap     map[string]struct{}	`json:"-"`
}

func (r *authorizeRequest) GetResponseTypes() []string {
	return r.ResponseTypes
}

func (r *authorizeRequest) AddResponseTypes(responseTypes ...string) {
	r.ResponseTypes = append(r.ResponseTypes, responseTypes...)
}

func (r *authorizeRequest) GetState() string {
	return r.State
}

func (r *authorizeRequest) SetState(state string) {
	r.State = state
}

func (r *authorizeRequest) HandledResponseType(responseType string) {
	r.handleMap[responseType] = struct{}{}
}

func (r *authorizeRequest) IsResponseTypeHandled(responseType string) bool {
	_, ok := r.handleMap[responseType]
	return ok
}


