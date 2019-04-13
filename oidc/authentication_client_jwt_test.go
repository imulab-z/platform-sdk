package oidc

import (
	"context"
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

func TestClientSecretJwtAuthentication(t *testing.T) {
	s := new(ClientSecretJwtAuthenticationTestSuite)
	suite.Run(t, s)
}

type ClientSecretJwtAuthenticationTestSuite struct {
	suite.Suite
	h *ClientSecretJwtAuthentication
}

func (s *ClientSecretJwtAuthenticationTestSuite) SetupTest() {
	s.h = &ClientSecretJwtAuthentication{
		TokenEndpointUrl: "http://test.org/token",
		SecretConversionFunc: nil,
		Lookup: new(clientJwtAuthLookup),
	}
}

func (s *ClientSecretJwtAuthenticationTestSuite) TestAuthenticate() {
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
				f.Set(spi.ParamClientAssertion, s.getSignedJwt("foo", fooSecret))
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
				f.Set(spi.ParamClientAssertion, s.getSignedJwt("bar", barSecret))
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

func (s *ClientSecretJwtAuthenticationTestSuite) getSignedJwt(clientId string, signingKey string) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key: []byte(signingKey),
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

type clientJwtAuthLookup struct {}

func (l *clientJwtAuthLookup) FindById(ctx context.Context, id string) (spi.OAuthClient, error) {
	switch id {
	case "foo":
		return new(clientJwtAuthFooClient), nil
	case "bar":
		return new(clientJwtAuthBarClient), nil
	default:
		return nil, errors.New("not found")
	}
}

const (
	fooSecret = "4C5D231E4E2D407F9B1A11E7E90EFDA1"
	barSecret = "2526118869DE4C20A4CE467D4D9F11BE"
)

type clientJwtAuthFooClient struct {
	*panicClient
}

func (c *clientJwtAuthFooClient) GetSecret() string {
	// 32 bytes - 256 bits
	return fooSecret
}

func (c *clientJwtAuthFooClient) GetId() string {
	return "foo"
}

func (c *clientJwtAuthFooClient) GetTokenEndpointAuthSigningAlg() string {
	return spi.SignAlgHS256
}

type clientJwtAuthBarClient struct {
	*panicClient
}

func (c *clientJwtAuthBarClient) GetSecret() string {
	// 32 bytes - 256 bits
	return barSecret
}

func (c *clientJwtAuthBarClient) GetId() string {
	return "bar"
}

func (c *clientJwtAuthBarClient) GetTokenEndpointAuthSigningAlg() string {
	return spi.SignAlgHS256
}