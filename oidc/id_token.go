package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/satori/go.uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"hash"
	"strings"
	"time"
)

type IdTokenStrategy interface {
	// Generate a new id token.
	NewToken(ctx context.Context, req oauth.Request) (string, error)
}

type JwxIdTokenStrategy struct {
	Issuer        string
	TokenLifespan time.Duration
	Jwks		  *jose.JSONWebKeySet
}

func (s *JwxIdTokenStrategy) NewToken(ctx context.Context, req oauth.Request) (string, error) {
	sess, ok := req.GetSession().(Session)
	if !ok {
		panic("must supply an oidc.Session")
	}

	client, ok := req.GetClient().(spi.OidcClient)
	if !ok {
		panic("must supply an OidcClient")
	}

	tok, err := s.sign(s.createClaims(sess, client), client)
	if err != nil {
		return "", err
	}

	if client.GetIdTokenEncryptedResponseAlg() != spi.EncryptAlgNone &&
		client.GetIdTokenEncryptedResponseEnc() != spi.EncAlgNone {
		return s.encrypt(tok, client)
	}

	return tok, nil
}

func (s *JwxIdTokenStrategy) encrypt(raw string, client spi.OidcClient) (string, error) {
	encrypter, err := s.createEncrypter(client)
	if err != nil {
		return "", err
	}

	if obj, err := encrypter.Encrypt([]byte(raw)); err != nil {
		return "", spi.ErrServerError(fmt.Errorf("failed to encrypt id_token: %s", err.Error()))
	} else {
		return obj.CompactSerialize()
	}
}

func (s *JwxIdTokenStrategy) createEncrypter(client spi.OidcClient) (jose.Encrypter, error) {
	// assuming client jwks is supplied or resolved.
	if len(client.GetJwks()) == 0 {
		return nil, spi.ErrServerError(errors.New("missing client json web key set"))
	}

	jwks := new(jose.JSONWebKeySet)
	if err := json.NewDecoder(strings.NewReader(client.GetJwks())).Decode(jwks); err != nil {
		return nil, spi.ErrServerError(fmt.Errorf("invalid client json web key set: %s", err.Error()))
	}

	key := oauth.FindEncryptionKeyByAlg(jwks, client.GetIdTokenEncryptedResponseAlg())
	if key == nil {
		return nil, spi.ErrServerError(errors.New("cannot find key to encrypt id_token for client"))
	}

	return jose.NewEncrypter(
		jose.ContentEncryption(client.GetIdTokenEncryptedResponseEnc()),
		jose.Recipient{
			Algorithm: jose.KeyAlgorithm(client.GetIdTokenEncryptedResponseAlg()),
			Key:       key,
			KeyID:     key.KeyID,
		},
		nil,
	)
}

func (s *JwxIdTokenStrategy) sign(claims []interface{}, client spi.OidcClient) (string, error) {
	switch client.GetIdTokenSignedResponseAlg() {
	case spi.SignAlgNone:
		m := make(map[string]interface{})
		// merge claims from different sources
		for _, c := range claims {
			switch c.(type) {
			case map[string]interface{}:
				for k, v := range c.(map[string]interface{}) {
					m[k] = v
				}
			case *jwt.Claims:
				if cb, err := json.Marshal(c); err != nil {
					return "", err
				} else if err := json.Unmarshal(cb, &m); err != nil {
					return "", err
				}
			default:
				return "", errors.New("unknown internal claim type")
			}
		}
		// encode
		if mb, err := json.Marshal(m); err != nil {
			return "", err
		} else {
			return string(mb), nil
		}
	default:
		signer, err := s.createSigner(client)
		if err != nil {
			return "", err
		}

		b := jwt.Signed(signer)
		for _, c := range claims {
			b = b.Claims(c)
		}

		return b.CompactSerialize()
	}
}

func (s *JwxIdTokenStrategy) createSigner(client spi.OidcClient) (jose.Signer, error) {
	key := oauth.FindSigningKeyByAlg(s.Jwks, client.GetIdTokenSignedResponseAlg())
	if key == nil {
		return nil, spi.ErrServerError(errors.New("cannot find key to sign id_token for client"))
	}

	opt := (&jose.SignerOptions{}).WithType("JWT")

	if signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(client.GetIdTokenSignedResponseAlg()),
		Key:       key,
	}, opt); err != nil {
		return nil, spi.ErrServerError(fmt.Errorf("failed to setup id_token signer: %s", err.Error()))
	} else {
		return signer, nil
	}
}

func (s *JwxIdTokenStrategy) createClaims(session Session, client spi.OidcClient) []interface{} {
	claims := make([]interface{}, 0)

	claims = append(claims, &jwt.Claims{
		ID:        uuid.NewV4().String(),
		Issuer:    s.Issuer,
		Subject:   session.GetObfuscatedSubject(),
		Audience:  []string{client.GetId()},
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(s.TokenLifespan)),
	})

	if len(session.GetIdTokenClaims()) > 0 {
		claims = append(claims, session.GetIdTokenClaims())
	}

	extra := map[string]interface{}{
		"auth_time":  session.GetAuthTime().Unix(),
		"nonce":      session.GetNonce(),
		"acr_values": session.GetAcrValues(),
	}
	if session.GetAuthTime().IsZero() {
		delete(extra, "auth_time")
	}
	if len(session.GetNonce()) == 0 {
		delete(extra, "nonce")
	}
	if len(session.GetAcrValues()) == 0 {
		delete(extra, "acr_values")
	}
	claims = append(claims, extra)

	return claims
}

type IdTokenHelper struct {
	Strategy IdTokenStrategy
}

func (h *IdTokenHelper) GenToken(ctx context.Context, req oauth.Request, resp oauth.Response) error {
	client, ok := req.GetClient().(spi.OidcClient)
	if !ok {
		panic("must be called with spi.OidcClient")
	}

	sess, ok := req.GetSession().(Session)
	if !ok {
		panic("must be called with oidc.Session")
	}

	for k, v := range map[string]string{
		oauth.Code:        "c_hash",
		oauth.AccessToken: "at_hash",
	} {
		if len(resp.GetString(k)) > 0 {
			if lmh := h.leftMostHash(resp.GetString(k), client.GetIdTokenSignedResponseAlg()); len(lmh) > 0 {
				sess.GetIdTokenClaims()[v] = lmh
			}
		}
	}

	if tok, err := h.Strategy.NewToken(ctx, req); err != nil {
		return err
	} else {
		resp.Set(IdToken, tok)
	}

	return nil
}

func (h *IdTokenHelper) leftMostHash(raw string, alg string) string {
	var hh hash.Hash

	switch alg {
	case spi.SignAlgRS256, spi.SignAlgES256, spi.SignAlgPS256:
		hh = sha256.New()
	case spi.SignAlgRS384, spi.SignAlgES384, spi.SignAlgPS384:
		hh = sha512.New384()
	case spi.SignAlgRS512, spi.SignAlgES512, spi.SignAlgPS512:
		hh = sha512.New()
	default:
		hh = nil
	}

	if hh != nil {
		hh.Write([]byte(raw))
		sum := hh.Sum(nil)
		return base64.StdEncoding.EncodeToString(sum[0 : len(sum)/2])
	}

	return ""
}
