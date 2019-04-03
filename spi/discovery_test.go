package spi

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestParseDiscoveryJson(t *testing.T) {
	rawJson := `
{
	"issuer": "imulab",
	"authorization_endpoint": "https://astrea.imulab.io/oauth/authorize",
	"token_endpoint": "https://astrea.imulab.io/oauth/token",
	"userinfo_endpoint": "https://astrea.imulab.io/userinfo",
	"jwks_uri": "https://astrea.imulab.io/jwks.json",
	"registration_endpoint": "https://astrea.imulab.io/client",
	"scopes_supported": [
		"openid", 
		"offline_access"
		],
	"response_types_supported": [
		"code", 
		"token", 
		"code id_token", 
		"token id_token", 
		"code token id_token"
		],
	"response_modes_supported": [
		"query", 
		"fragment"
		],
	"grant_types_supported": [
		"authorization_code", 
		"implicit", 
		"client_credentials", 
		"refresh_token"
		],
	"acr_values_supported": [],
	"subject_types_supported": [
		"public", 
		"pairwise"
		],
	"id_token_signing_alg_values_supported": [
		"RS256"
		],
	"id_token_encryption_alg_values_supported": [],
	"id_token_encryption_enc_values_supported": [],
	"userinfo_signing_alg_values_supported": [
		"RS256"
		],
	"userinfo_encryption_alg_values_supported": [],
	"userinfo_encryption_enc_values_supported": [],
	"request_object_signing_alg_values_supported": [
		"RS256"
		],
	"request_object_encryption_alg_values_supported": [],
	"request_object_encryption_enc_values_supported": [],
	"token_endpoint_auth_methods_supported": [
		"client_secret_basic", 
		"client_secret_post", 
		"private_key_jwt"
		],
	"token_endpoint_auth_signing_alg_values_supported": [
		"RS256"
		],
	"display_values_supported": [
		"page",
		"popup"
		],
	"service_documentation": "https://astrea.imulab.io/docs",
	"ui_locales_supported": [
		"en-US", 
		"zh-CN"
		],
	"request_parameter_supported": true,
	"request_uri_parameter_supported": true,
	"require_request_uri_registration": true,
	"op_policy_uri": "https://astrea.imulab.io/policy",
	"op_tos_uri": "https://astrea.imulab.io/tos"
}
`
	discovery := new(Discovery)
	err := json.NewDecoder(bytes.NewBufferString(rawJson)).Decode(discovery)
	if err != nil {
		t.Error(err)
	}
}
