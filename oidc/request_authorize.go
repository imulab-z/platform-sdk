package oidc

import "github.com/imulab-z/platform-sdk/oauth"

type AuthorizeRequest interface {
	oauth.AuthorizeRequest
	// response_mode
	GetResponseMode() string
	SetResponseMode(mode string)
	// nonce
	GetNonce() string
	SetNonce(nonce string)
	// display
	GetDisplay() string
	SetDisplay(display string)
	// prompts
	GetPrompts() []string
	AddPrompt(prompts ...string)
	// max_age
	GetMaxAge() uint64
	SetMaxAge(maxAge uint64)
	// ui_locales
	GetUiLocales() []string
	AddUiLocale(locales ...string)
	// id_token_hint
	GetIdTokenHint() string
	SetIdTokenHint(hint string)
	// acr_values
	GetAcrValues() []string
	AddAcrValue(values ...string)
	// claims
	GetClaims() map[string]interface{}
	// claims_locales
	GetClaimsLocales() []string
	AddClaimsLocale(locales ...string)
	// iss
	GetIss() string
	SetIss(iss string)
	// target_link_uri
	GetTargetLinkUri() string
	SetTargetLinkUri(uri string)
}

func NewAuthorizeRequest() AuthorizeRequest {
	return &authorizeRequest{
		oidcRequest: NewRequest().(*oidcRequest),
		ResponseTypes: make([]string, 0),
		Scopes:        make([]string, 0),
		State:         "",
		handleMap:     make(map[string]struct{}),
		ResponseMode:  "",
		Nonce:         "",
		Display:       "",
		Prompts:       make([]string, 0),
		MaxAge:        0,
		UiLocales:     make([]string, 0),
		IdTokenHint:   "",
		AcrValues:     make([]string, 0),
		Claims:        make(map[string]interface{}),
		ClaimsLocales: make([]string, 0),
		Iss:           "",
		TargetLinkUri: "",
	}
}

type authorizeRequest struct {
	*oidcRequest
	ResponseTypes []string               `json:"response_types"`
	Scopes        []string               `json:"scopes"`
	State         string                 `json:"state"`
	handleMap     map[string]struct{}    `json:"-"`
	ResponseMode  string                 `json:"response_mode"`
	Nonce         string                 `json:"nonce"`
	Display       string                 `json:"display"`
	Prompts       []string               `json:"prompts"`
	MaxAge        uint64                 `json:"max_age"`
	UiLocales     []string               `json:"ui_locales"`
	IdTokenHint   string                 `json:"id_token_hint"`
	AcrValues     []string               `json:"acr_values"`
	Claims        map[string]interface{} `json:"claims"`
	ClaimsLocales []string               `json:"claims_locales"`
	Iss           string                 `json:"iss"`
	TargetLinkUri string                 `json:"target_link_uri"`
}

func (r *authorizeRequest) GetResponseTypes() []string {
	return r.ResponseTypes
}

func (r *authorizeRequest) GetScopes() []string {
	return r.Scopes
}

func (r *authorizeRequest) GetState() string {
	return r.State
}

func (r *authorizeRequest) HandledResponseType(responseType string) {
	r.handleMap[responseType] = struct{}{}
}

func (r *authorizeRequest) IsResponseTypeHandled(responseType string) bool {
	_, ok := r.handleMap[responseType]
	return ok
}

func (r *authorizeRequest) AddResponseTypes(responseTypes ...string) {
	r.ResponseTypes = append(r.ResponseTypes, responseTypes...)
}

func (r *authorizeRequest) AddScopes(scopes ...string) {
	r.Scopes = append(r.Scopes, scopes...)
}

func (r *authorizeRequest) SetState(state string) {
	r.State = state
}

func (r *authorizeRequest) GetResponseMode() string {
	return r.ResponseMode
}

func (r *authorizeRequest) SetResponseMode(mode string) {
	r.ResponseMode = mode
}

func (r *authorizeRequest) GetNonce() string {
	return r.Nonce
}

func (r *authorizeRequest) SetNonce(nonce string) {
	r.Nonce = nonce
}

func (r *authorizeRequest) GetDisplay() string {
	return r.Display
}

func (r *authorizeRequest) SetDisplay(display string) {
	r.Display = display
}

func (r *authorizeRequest) GetPrompts() []string {
	return r.Prompts
}

func (r *authorizeRequest) AddPrompt(prompts ...string) {
	r.Prompts = append(r.Prompts, prompts...)
}

func (r *authorizeRequest) GetMaxAge() uint64 {
	return r.MaxAge
}

func (r *authorizeRequest) SetMaxAge(maxAge uint64) {
	r.MaxAge = maxAge
}

func (r *authorizeRequest) GetUiLocales() []string {
	return r.UiLocales
}

func (r *authorizeRequest) AddUiLocale(locales ...string) {
	r.UiLocales = append(r.UiLocales, locales...)
}

func (r *authorizeRequest) GetIdTokenHint() string {
	return r.IdTokenHint
}

func (r *authorizeRequest) SetIdTokenHint(hint string) {
	r.IdTokenHint = hint
}

func (r *authorizeRequest) GetAcrValues() []string {
	return r.AcrValues
}

func (r *authorizeRequest) AddAcrValue(values ...string) {
	r.AcrValues = append(r.AcrValues, values...)
}

func (r *authorizeRequest) GetClaims() map[string]interface{} {
	return r.Claims
}

func (r *authorizeRequest) GetClaimsLocales() []string {
	return r.ClaimsLocales
}

func (r *authorizeRequest) AddClaimsLocale(locales ...string) {
	r.ClaimsLocales = append(r.ClaimsLocales, locales...)
}

func (r *authorizeRequest) GetIss() string {
	return r.Iss
}

func (r *authorizeRequest) SetIss(iss string) {
	r.Iss = iss
}

func (r *authorizeRequest) GetTargetLinkUri() string {
	return r.TargetLinkUri
}

func (r *authorizeRequest) SetTargetLinkUri(uri string) {
	r.TargetLinkUri = uri
}
