package spi

type Discovery struct {
	Issuer 									string		`json:"issuer"`
	AuthorizationEndpoint					string 		`json:"authorization_endpoint"`
	TokenEndpoint							string 		`json:"token_endpoint"`
	UserInfoEndpoint						string 		`json:"userinfo_endpoint"`
	JwksUri									string 		`json:"jwks_uri"`
	RegistrationEndpoint					string 		`json:"registration_endpoint"`
	ScopesSupported							[]string 	`json:"scopes_supported"`
	ResponseTypesSupported					[]string 	`json:"response_types_supported"`
	ResponseModesSupported					[]string 	`json:"response_modes_supported"`
	GrantTypesSupported						[]string 	`json:"grant_types_supported"`
	AcrValuesSupported						[]string 	`json:"acr_values_supported"`
	SubjectTypesSupported					[]string 	`json:"subject_types_supported"`
	IdTokenSigningAlgSupported				[]string	`json:"id_token_signing_alg_values_supported"`
	IdTokenEncryptAlgSupported 				[]string 	`json:"id_token_encryption_alg_values_supported"`
	IdTokenEncryptEncSupported				[]string	`json:"id_token_encryption_enc_values_supported"`
	UserInfoSigningAlgSupported				[]string	`json:"userinfo_signing_alg_values_supported"`
	UserInfoEncryptAlgSupported				[]string	`json:"userinfo_encryption_alg_values_supported"`
	UserInfoEncryptEncSupported				[]string	`json:"userinfo_encryption_enc_values_supported"`
	ReqObjSigningAlgSupported				[]string	`json:"request_object_signing_alg_values_supported"`
	ReqObjEncryptAlgSupported				[]string	`json:"request_object_encryption_alg_values_supported"`
	ReqObjEncryptEncSupported				[]string	`json:"request_object_encryption_enc_values_supported"`
	TokenEndpointAuthMethodsSupported		[]string	`json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgSupported	[]string	`json:"token_endpoint_auth_signing_alg_values_supported"`
	DisplayValuesSupported					[]string	`json:"display_values_supported"`
	ClaimTypesSupported						[]string	`json:"claim_types_supported"`
	ClaimsSupported							[]string	`json:"claims_supported"`
	ServiceDocumentation					string 		`json:"service_documentation"`
	ClaimsLocalesSupported					[]string	`json:"claims_locales_supported"`
	UiLocalesSupported						[]string	`json:"ui_locales_supported"`
	ClaimsParameterSupported				bool		`json:"claims_parameter_supported"`
	RequestParameterSupported				bool		`json:"request_parameter_supported"`
	RequestUriParameterSupported			bool		`json:"request_uri_parameter_supported"`
	RequireRequestUriRegistration			bool 		`json:"require_request_uri_registration"`
	OpPolicyUri								string		`json:"op_policy_uri"`
	OpTosUri								string 		`json:"op_tos_uri"`
}