package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientSecretPostAuthentication(t *testing.T) {
	s := new(ClientSecretPostAuthenticationTestSuite)
	suite.Run(t, s)
}

type ClientSecretPostAuthenticationTestSuite struct {
	suite.Suite
	h *ClientSecretPostAuthentication
}

func (s *ClientSecretPostAuthenticationTestSuite) SetupTest() {
	s.h = &ClientSecretPostAuthentication{
		SecretComparator: nil,
		Lookup: new(postAuthTestClientLookup),
	}
}

func (s *ClientSecretPostAuthenticationTestSuite) TestAuthenticate() {
	for _, v := range []struct {
		name        string
		reqFunc     func() *http.Request
		expectError bool
	}{
		{
			name: "correct authentication",
			reqFunc: func() *http.Request {
				f := url.Values{}
				f.Set(spi.ParamClientId, "foo")
				f.Set(spi.ParamClientSecret, "s3cret")
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
				f.Set(spi.ParamClientSecret, "invalid")
				r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(f.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

type postAuthTestClientLookup struct{}

func (l *postAuthTestClientLookup) FindById(ctx context.Context, id string) (spi.OAuthClient, error) {
	return new(postAuthTestClient), nil
}

type postAuthTestClient struct {
	*panicClient
}

func (c *postAuthTestClient) GetId() string {
	return "foo"
}

func (c *postAuthTestClient) GetSecret() string {
	return "s3cret"
}
