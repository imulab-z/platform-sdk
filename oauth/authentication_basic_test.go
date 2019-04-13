package oauth

import (
	"context"
	"encoding/base64"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientSecretBasicAuthentication(t *testing.T) {
	s := new(ClientSecretBasicAuthenticationTestSuite)
	suite.Run(t, s)
}

type ClientSecretBasicAuthenticationTestSuite struct {
	suite.Suite
	h *ClientSecretBasicAuthentication
}

func (s *ClientSecretBasicAuthenticationTestSuite) SetupTest() {
	s.h = &ClientSecretBasicAuthentication{
		Lookup:           new(basicAuthTestClientLookup),
		SecretComparator: nil,
	}
}

func (s *ClientSecretBasicAuthenticationTestSuite) TestAuthenticate() {
	for _, v := range []struct {
		name        string
		reqFunc     func() *http.Request
		expectError bool
	}{
		{
			name: "correct authentication",
			reqFunc: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/token", nil)
				r.Header.Set(AuthorizationHeader, Basic + Space + s.base64("foo:s3cret"))
				return r
			},
			expectError: false,
		},
		{
			name: "failed authentication",
			reqFunc: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/token", nil)
				r.Header.Set(AuthorizationHeader, Basic + Space + s.base64("foo:invalid"))
				return r
			},
			expectError: true,
		},
		{
			name: "invalid header",
			reqFunc: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/token", nil)
				r.Header.Set(AuthorizationHeader, "invalid")
				return r
			},
			expectError: true,
		},
	} {
		_, err := s.h.Authenticate(context.Background(), v.reqFunc())
		if v.expectError {
			s.Assert().NotNil(err)
		} else {
			s.Assert().Nil(err)
		}
	}
}

func (s *ClientSecretBasicAuthenticationTestSuite) base64(raw string) string {
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

type basicAuthTestClientLookup struct{}

func (l *basicAuthTestClientLookup) FindById(ctx context.Context, id string) (spi.OAuthClient, error) {
	return new(basicAuthTestClient), nil
}

type basicAuthTestClient struct {
	*panicClient
}

func (c *basicAuthTestClient) GetId() string {
	return "foo"
}

func (c *basicAuthTestClient) GetSecret() string {
	return "s3cret"
}
