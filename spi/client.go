package spi

// interface for representing a client in the OAuth 2.0 context.
type OAuthClient interface {
	// Returns an universal client identifier.
	GetId() string
	// Returns the client's name.
	GetName() string
	// Returns client type.
	// [confidential|public]
	GetType() string
	// Returns registered redirect URIs.
	GetRedirectUris() []string
	// Returns registered response types.
	// [code|token]
	GetResponseTypes() []string
	// Returns registered grant types.
	// [authorization_code|implicit|password|client_credentials|refresh_token]
	GetGrantTypes() []string
	// Returns registered scopes.
	GetScopes() []string
}

type OidcClient interface {
	OAuthClient
}