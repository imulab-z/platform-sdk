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

// Add-on interface for client to implement if it decides to return client secret data (plain, hashed, or encrypted).
// This is designed as a separate interface to generally discourage implementation to transfer client secret data
// across network, so that developers that require client secret data will consciously do so by implementing this
// interface.
type ClientSecretAware interface {
	// Returns the client secret in plain, hashed, or encrypted form.
	GetSecret() string
}

type OidcClient interface {
	OAuthClient
	// application_type
	// Optional. Kind of the application. Default should be set to web.
	GetApplicationType() string
	// contacts
	// Optional. Array of e-mails for people responsible for this client.
	GetContacts() string
	// logo_uri
	// Optional. URL that references the client logo. If present, will be displayed to the end user during approval.
	GetLogoUri() string
	// client_uri
	// Optional. URL to the home page of the client. If present, will be enabled for the end user to follow during approval.
	GetClientUri() string
	// policy_uri
	// Optional. URL the RP provides to inform the end user how their profile data will be used. If present, will be
	// displayed to the end user during approval.
	GetPolicyUri() string
	// tos_uri
	// Optional. URL the RP provides to inform the end user about their terms of service. If present, will be displayed
	// to the end user during approval.
	GetTosUri() string
	// jwks_uri
	// Optional. URL for the client's JSON Web Key Set. If registered, the server should download and cache it to avoid
	// request time round trip.
	GetJwksUri() string
	// jwks
	// Optional. Client's JSON Web Key Set by value.
	GetJwks() string
	// sector_identifier_uri
	// Optional. URL using https scheme whose host component will be utilized during pairwise pseudonymous subject value
	// calculation. The URL itself should point to a file with single JSON array of redirectUri values.
	GetSectorIdentifierUri() string
	// subject_type
	// Optional. The subject type of this client. This value determines how pseudonymous subject value is calculated.
	GetSubjectType() string
	// id_token_signed_response_alg
	// Optional. The JWT 'alg' header value. 'none' MUST NOT be used unless client does not use token endpoint
	// (reflected by its registered [responseTypes]). By default, this should be set to RS256. The public key for
	// validating the signature should be retrievable via jwks_uri or jwks.
	GetIdTokenSignedResponseAlg() string
	// id_token_encrypted_response_alg
	// Optional. The JWE 'alg' header value. If value is 'none', id_token will only be signed. Otherwise, it will be
	// signed and then encrypted.
	GetIdTokenEncryptedResponseAlg() string
	// id_token_encrypted_response_enc
	// Optional. The JWE 'enc' header value. This value should be specified when id_token_encrypted_response_alg is
	// specified. By default, this value is A128CBC-HS256.
	GetIdTokenEncryptedResponseEnc() string
	// request_object_signing_alg
	// Optional. The JWT 'alg' header value. If not signed with this algorithm, all request object sent to OP must be
	// rejected. By default, this value is RS256. 'none' may be used, but not recommended unless request object is also
	// encrypted.
	GetRequestObjectSigningAlg() string
	// request_object_encryption_alg
	// Optional. The JWE 'alg' header value. If a symmetric algorithm is used, the OP should use the client's secret as
	// key. If 'none', the OP will treat request objects as unencrypted.
	GetRequestObjectEncryptionAlg() string
	// request_object_encryption_enc
	// Optional. The JWE 'enc' header value. By default, this value is A128CBC-HS256.
	GetRequestObjectEncryptionEnc() string
	// userinfo_signed_response_alg
	// Optional. The JWT 'alg' header value. By default, if omitted, the OP returns user info as an UTF-8 encoded JSON
	// object with 'application/json' set as Content-Type header.
	GetUserInfoSignedResponseAlg() string
	// userinfo_encrypted_response_alg
	// Optional. The JWE 'alg' header value. It the value is 'none', no encryption/decryption will be performed by OP.
	GetUserInfoEncryptedResponseAlg() string
	// userinfo_encrypted_response_enc
	// Optional. The JWE 'enc' header value. By default, this value is A128CBC-HS256.
	GetUserInfoEncryptedResponseEnc() string
	// token_endpoint_auth_method
	// Optional. The method employed at the token endpoint to authenticate the client. If omitted, the default method
	// used should be client_secret_basic.
	GetTokenEndpointAuthMethod() string
	// token_endpoint_auth_signing_alg
	// Optional. JWA that must be used for signing the JWT used to authenticate the client at the token endpoint for the
	// private_key_jwt and client_secret_jwt authentication methods. Server should support RS256. none MUST NOT be used.
	GetTokenEndpointAuthSigningAlg() string
	// default_max_age
	// Optional. Specifies the end user must be actively authenticated if the end user is authenticated longer ago than
	// the number of seconds specified by this value. This value can be override by the max_age parameter in the request.
	// By default, the value '0' means no default max age. In this case, if no max_age is specified by the request, the
	// OP does not consider expiration when dealing with authentication sessions.
	GetDefaultMaxAge() uint64
	// require_auth_time
	// Optional. Boolean value indicating that auth_time claim is required. By default, the value is false. However,
	// even when false, auth_time can still be dynamically requested by requests utilizing the idTokenClaims field.
	IsAuthTimeRequired() bool
	// default_acr_values
	// Optional. A list of default acr values that the OP is requested to use during the request.
	GetDefaultAcrValues() []string
	// initiate_login_uri
	// Optional. URL using https scheme that a third party will use to initiate a login by the RP. If this value is
	// provided, the OP should direct end-user to this address when login is required. Otherwise, end-user will be
	// directed to server's default login page. This url must accept both GET and POST requests. The client must
	// understand login_hint and iss parameters and support target_link_uri parameter.
	GetInitiateLoginUri() string
	// request_uris
	// Optional. Array of request_uri values pre-registered by the client to be used at request. Servers can cache the
	// contents of these value before to avoid round trip at request time. Uris can include a base64 encoded SHA-256
	// hash of file contents as fragment component to serve as a version. Server should retire cached requests and fetch
	// new ones when these hash does not match.
	GetRequestUris() []string
}
