package oauth

import (
	"context"
	"errors"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNoneAuthentication(t *testing.T) {
	s := new(NoneAuthenticationTestSuite)
	suite.Run(t, s)
}

type NoneAuthenticationTestSuite struct {
	suite.Suite
	h *NoneAuthentication
}

func (s *NoneAuthenticationTestSuite) SetupTest() {
	s.h = &NoneAuthentication{
		Lookup: new(noneAuthTestClientLookup),
	}
}

func (s *NoneAuthenticationTestSuite) TestAuthenticate() {
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
				f.Set(spi.ParamClientId, "bar")
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

type noneAuthTestClientLookup struct{}

func (l *noneAuthTestClientLookup) FindById(ctx context.Context, id string) (spi.OAuthClient, error) {
	switch id {
	case "foo":
		return new(noneAuthTestFooClient), nil
	case "bar":
		return new(noneAuthTestBarClient), nil
	default:
		return nil, errors.New("not found")
	}

}

type noneAuthTestFooClient struct {
	*panicClient
}

func (c *noneAuthTestFooClient) GetId() string {
	return "foo"
}

func (c *noneAuthTestFooClient) GetType() string {
	return spi.ClientTypePublic
}

type noneAuthTestBarClient struct {
	*panicClient
}

func (c *noneAuthTestBarClient) GetId() string {
	return "bar"
}

func (c *noneAuthTestBarClient) GetType() string {
	return spi.ClientTypeConfidential
}
