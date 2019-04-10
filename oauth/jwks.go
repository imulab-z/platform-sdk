package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"gopkg.in/square/go-jose.v2"
)

func FindSigningKeyById(jwks *jose.JSONWebKeySet, kid string) *jose.JSONWebKey {
	keys := jwks.Key(kid)
	if len(keys) == 0 {
		return nil
	}
	return &keys[0]
}

func FindVerificationKeyById(jwks *jose.JSONWebKeySet, kid string) *jose.JSONWebKey {
	keys := jwks.Key(kid)
	if len(keys) == 0 {
		return nil
	}

	var key jose.JSONWebKey
	switch keys[0].Key.(type) {
	case []byte:
		key = keys[0]
	default:
		key = keys[0].Public()
	}

	return &key
}

func FindSigningKeyByAlg(jwks *jose.JSONWebKeySet, alg string) *jose.JSONWebKey {
	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			return &jwk
		}
	}
	return nil
}

func FindVerificationKeyByAlg(jwks *jose.JSONWebKeySet, alg string) *jose.JSONWebKey {
	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			var key jose.JSONWebKey
			switch jwk.Key.(type) {
			case []byte:
				key = jwk
			default:
				key = jwk.Public()
			}
			return &key
		}
	}
	return nil
}

func FindEncryptionKeyByAlg(jwks *jose.JSONWebKeySet, alg string) *jose.JSONWebKey {
	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			switch jwk.Key.(type) {
			case []byte:
				return &jwk
			default:
				if jwk.IsPublic() {
					return &jwk
				} else {
					pk := jwk.Public()
					return &pk
				}
			}
		}
	}
	return nil
}

func MustNewJwksWithRsaKeyForSigning(kid string) *jose.JSONWebKeySet {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key: privateKey,
				Algorithm: string(jose.RS256),
				Use: "sign",
				KeyID: kid,
			},
		},
	}
}