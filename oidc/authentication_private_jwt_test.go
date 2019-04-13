package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/suite"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPrivateKeyJwtAuthentication(t *testing.T) {
	s := new(PrivateKeyJwtAuthenticationTestSuite)
	suite.Run(t, s)
}

type PrivateKeyJwtAuthenticationTestSuite struct {
	suite.Suite
	h *PrivateKeyJwtAuthentication
	fooPrivateKey	*rsa.PrivateKey
	fooPublicKey	*rsa.PublicKey
	barPrivateKey	*rsa.PrivateKey
	barPublicKey	*rsa.PublicKey
}

func (s *PrivateKeyJwtAuthenticationTestSuite) SetupTest() {
	s.fooPrivateKey, s.fooPublicKey = s.genKey()
	s.barPrivateKey, s.barPublicKey = s.genKey()

	s.h = &PrivateKeyJwtAuthentication{
		TokenEndpointUrl: "http://test.org/token",
		Lookup: &privateKeyJwtAuthClientLookup {
			db: map[string]spi.OAuthClient{
				"foo": newPrivateKeyJwtAuthClient("foo", s.fooPublicKey),
				"bar": newPrivateKeyJwtAuthClient("bar", s.barPublicKey),
			},
		},
	}
}

func (s *PrivateKeyJwtAuthenticationTestSuite) TestAuthenticate() {
	for _, v := range []struct{
		name 		string
		reqFunc		func() *http.Request
		expectError	bool
	}{
		{
			name: "correct authentication",
			reqFunc: func() *http.Request {
				f := url.Values{}
				f.Set(spi.ParamClientId, "foo")
				f.Set(spi.ParamClientAssertionType, spi.ClientAssertionTypeJwtBearer)
				f.Set(spi.ParamClientAssertion, s.getSignedJwt("foo", s.fooPrivateKey))
				r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(f.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			},
			expectError: false,
		},
		{
			name: "failed authentication",
			reqFunc: func() *http.Request {
				f := url.Values{}
				f.Set(spi.ParamClientId, "foo")
				f.Set(spi.ParamClientAssertionType, spi.ClientAssertionTypeJwtBearer)
				f.Set(spi.ParamClientAssertion, s.getSignedJwt("foo", s.barPrivateKey))
				r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(f.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			},
			expectError: true,
		},
	}{
		c, err := s.h.Authenticate(context.Background(), v.reqFunc())
		if v.expectError {
			s.Assert().NotNil(err)
		} else {
			s.Assert().Nil(err)
			s.Assert().NotNil(c)
		}
	}
}

func (s *PrivateKeyJwtAuthenticationTestSuite) getSignedJwt(clientId string, signingKey *rsa.PrivateKey) string {

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: &jose.JSONWebKey{
			KeyID: clientId,
			Use: "sign",
			Key: signingKey,
			Algorithm: string(jose.RS256),
		},
	}, nil)
	s.Require().Nil(err)

	tok, err := jwt.Signed(signer).Claims(&jwt.Claims{
		ID: uuid.NewV4().String(),
		Issuer: clientId,
		Subject: clientId,
		Audience: jwt.Audience{s.h.TokenEndpointUrl},
		Expiry: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
	}).CompactSerialize()
	s.Require().Nil(err)

	return tok
}

func (s *PrivateKeyJwtAuthenticationTestSuite) genKey() (*rsa.PrivateKey, *rsa.PublicKey) {
	k1, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().Nil(err)
	return k1, &k1.PublicKey
}

type privateKeyJwtAuthClientLookup struct {
	db map[string]spi.OAuthClient
}

func (l *privateKeyJwtAuthClientLookup) FindById(ctx context.Context, id string) (spi.OAuthClient, error) {
	if c, ok := l.db[id]; ok {
		return c, nil
	} else {
		return nil, errors.New("not found")
	}
}

func newPrivateKeyJwtAuthClient(id string, publicKey *rsa.PublicKey) spi.OAuthClient {
	jwks, err := json.Marshal(&jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Algorithm: string(jose.RS256),
				Key: publicKey,
				Use: "sign",
				KeyID: id,
			},
		},
	})
	if err != nil {
		panic(err)
	}

	return &privateKeyJwtAuthClient{
		id: id,
		jwks: string(jwks),
	}
}

type privateKeyJwtAuthClient struct {
	*panicClient
	id 		string
	jwks	string
}

func (c *privateKeyJwtAuthClient) GetId() string {
	return c.id
}

func (c *privateKeyJwtAuthClient) GetJwks() string {
	return c.jwks
}

func (c *privateKeyJwtAuthClient) GetTokenEndpointAuthSigningAlg() string {
	return spi.SignAlgRS256
}