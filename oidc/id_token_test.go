package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/imulab-z/platform-sdk/test"
	"github.com/stretchr/testify/suite"
	"gopkg.in/square/go-jose.v2"
	"testing"
	"time"
)

func TestJwxIdTokenStrategy(t *testing.T) {
	s := new(JwxIdTokenStrategyTestSuite)
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()
	suite.Run(t, s)
}

type JwxIdTokenStrategyTestSuite struct {
	suite.Suite
	strategy	*JwxIdTokenStrategy
}

func (s *JwxIdTokenStrategyTestSuite) SetupTest() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Assert().Nil(err)

	s.strategy = &JwxIdTokenStrategy{
		Jwks: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key: privateKey,
					Algorithm: string(jose.RS256),
					Use: "sign",
					KeyID: "test-key",
				},
			},
		},
		Issuer: "test",
		TokenLifespan: 30 * time.Minute,
	}
}

func (s *JwxIdTokenStrategyTestSuite) TestSignOnlyIdToken() {
	req := NewAuthorizeRequest()
	req.SetId("567C6B7B-93B0-44CC-B820-6598E358466F")

	sess := NewSession()
	sess.SetSubject("test user")
	sess.SetObfuscatedSubject("test user")
	req.SetSession(sess)

	client := new(jwxIdTokenStrategyTestSuiteOnlyClient)
	client.RequireIdTokenSigning = true
	client.RequireIdTokenEncryption = false
	req.SetClient(client)

	tok, err := s.strategy.NewToken(context.Background(), req)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(tok)
}

func (s *JwxIdTokenStrategyTestSuite) TestSignAndEncryptIdToken() {
	req := NewAuthorizeRequest()
	req.SetId("567C6B7B-93B0-44CC-B820-6598E358466F")

	sess := NewSession()
	sess.SetSubject("test user")
	sess.SetObfuscatedSubject("test user")
	req.SetSession(sess)

	client := new(jwxIdTokenStrategyTestSuiteOnlyClient)
	client.RequireIdTokenSigning = true
	client.RequireIdTokenEncryption = true
	req.SetClient(client)

	tok, err := s.strategy.NewToken(context.Background(), req)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(tok)
}

func (s *JwxIdTokenStrategyTestSuite) TestEncryptOnlyIdToken() {
	req := NewAuthorizeRequest()
	req.SetId("567C6B7B-93B0-44CC-B820-6598E358466F")

	sess := NewSession()
	sess.SetSubject("test user")
	sess.SetObfuscatedSubject("test user")
	req.SetSession(sess)

	client := new(jwxIdTokenStrategyTestSuiteOnlyClient)
	client.RequireIdTokenSigning = false
	client.RequireIdTokenEncryption = true
	req.SetClient(client)

	tok, err := s.strategy.NewToken(context.Background(), req)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(tok)
}

type jwxIdTokenStrategyTestSuiteOnlyClient struct {
	*test.PanicClient
	jwks						string
	RequireIdTokenSigning		bool
	RequireIdTokenEncryption 	bool
}

func (c *jwxIdTokenStrategyTestSuiteOnlyClient) GetId() string {
	return "e79e14ed-da33-4d0b-87a7-f95f1617ab41"
}

func (c *jwxIdTokenStrategyTestSuiteOnlyClient) GetJwks() string {
	if len(c.jwks) == 0 {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		jwks, err := json.Marshal(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Algorithm: spi.EncryptAlgRSAOAEP,
					KeyID: "0dde37a4-8fc9-4514-a6b4-36339e6d17c4",
					Key: &privateKey.PublicKey,
					Use: "encryption",
				},
			},
		})
		if err != nil {
			panic(err)
		}

		c.jwks = string(jwks)
	}
	return c.jwks
}

func (c *jwxIdTokenStrategyTestSuiteOnlyClient) GetIdTokenSignedResponseAlg() string {
	if c.RequireIdTokenSigning {
		return spi.SignAlgRS256
	} else {
		return spi.SignAlgNone
	}
}

func (c *jwxIdTokenStrategyTestSuiteOnlyClient) GetIdTokenEncryptedResponseAlg() string {
	if c.RequireIdTokenEncryption {
		return spi.EncryptAlgRSAOAEP
	} else {
		return spi.EncryptAlgNone
	}

}

func (c *jwxIdTokenStrategyTestSuiteOnlyClient) GetIdTokenEncryptedResponseEnc() string {
	if c.RequireIdTokenEncryption {
		return spi.EncAlgA128GCM
	} else {
		return spi.EncAlgNone
	}
}
