package spi

// Response Types
const (
	ResponseTypeCode    = "code"
	ResponseTypeToken   = "token"
	ResponseTypeIdToken = "id_token"
)

// Grant Types
const (
	GrantTypeCode     = "authorization_code"
	GrantTypeImplicit = "implicit"
	GrantTypePassword = "password"
	GrantTypeClient   = "client_credentials"
	GrantTypeRefresh  = "refresh_token"
)

// Standard scopes
const (
	ScopeOffline       = "offline"
	ScopeOfflineAccess = "offline_access"
)

// application_type
const (
	AppTypeWeb = "web"
	AppTypeNative = "native"
)

// subject_type
const (
	SubjectTypePublic = "public"
	SubjectTypePairwise = "pairwise"
)

// signing algorithms
const (
	SignAlgHS256 = "HS256"
	SignAlgHS384 = "HS384"
	SignAlgHS512 = "HS512"
	SignAlgRS256 = "RS256"
	SignAlgRS384 = "RS384"
	SignAlgRS512 = "RS512"
	SignAlgES256 = "ES256"
	SignAlgES384 = "ES384"
	SignAlgES512 = "ES512"
	SignAlgPS256 = "PS256"
	SignAlgPS384 = "PS384"
	SignAlgPS512 = "PS512"
	SignAlgNone = "none"
)

// encryption algorithms
const (
	EncryptAlgRSA15            = "RSA1_5"
	EncryptAlgRSAOAEP          = "RSA-OAEP"
	EncryptAlgRSAOAEP256       = "RSA-OAEP-256"
	EncryptAlgECDHES           = "ECDH-ES"
	EncryptAlgECDHESA128KW     = "ECDH-ES+A128KW"
	EncryptAlgECDHESA192KW     = "ECDH-ES+A192KW"
	EncryptAlgECDHESA256KW     = "ECDH-ES+A256KW"
	EncryptAlgA128KW           = "A128KW"
	EncryptAlgA192KW           = "A192KW"
	EncryptAlgA256KW           = "A256KW"
	EncryptAlgA128GCMKW        = "A128GCMKW"
	EncryptAlgA192GCMKW        = "A192GCMKW"
	EncryptAlgA256GCMKW        = "A256GCMKW"
	EncryptAlgPBES2HS256A128KW = "PBES2-HS256+A128KW"
	EncryptAlgPBES2HS384A192KW = "PBES2-HS384+A192KW"
	EncryptAlgPBES2HS512A256KW = "PBES2-HS512+A256KW"
	EncryptAlgDirect           = "dir"
	EncryptAlgNone             = "none"
)

// encryption encodings
const (
	EncAlgA128CBCHS256 = "A128CBC-HS256"
	EncAlgA192CBCHS384 = "A192CBC-HS384"
	EncAlgA256CBCHS512 = "A256CBC-HS512"
	EncAlgA128GCM = "A128GCM"
	EncAlgA192GCM = "A192GCM"
	EncAlgA256GCM = "A256GCM"
	EncAlgNone = "none"
)

// token_endpoint_auth_method
const (
	AuthMethodClientSecretPost = "client_secret_post"
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretJwt = "client_secret_jwt"
	AuthMethodPrivateKeyJwt = "private_key_jwt"
	AuthMethodNone = "none"
)

// Parameters
const (
	ParamClientId     = "client_id"
	ParamResponseType = "response_type"
	ParamRedirectUri  = "redirect_uri"
	ParamScope        = "scope"
	ParamState        = "state"
)
