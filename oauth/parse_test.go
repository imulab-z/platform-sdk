package oauth

import (
	"context"
	"errors"
	"fmt"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/imulab-z/platform-sdk/test"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHttpRequestParser(t *testing.T) {
	s := new(HttpRequestParserTestSuite)
	suite.Run(t, s)
}

type HttpRequestParserTestSuite struct {
	suite.Suite
	parser   *httpRequestParser
	clientId string
}

func (s *HttpRequestParserTestSuite) SetupTest() {
	client := new(test.MockClient)
	s.clientId = client.GetId()

	lookup := new(test.MockClientLookup)
	lookup.On("FindById", client.GetId()).Return(client, nil)
	lookup.On("FindById", "foo").Return(nil, errors.New("client not found"))

	s.parser = &httpRequestParser{
		ClientLookup: lookup,
	}
}

func (s *HttpRequestParserTestSuite) TestParseAuthorizeRequest() {
	r := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf(
			"http://test.org/oauth/authorize?client_id=%s&response_type=%s&redirect_uri=%s&scope=%s&state=%s",
			s.clientId,
			spi.ResponseTypeCode,
			"https://mock.test.org/callback",
			"foo",
			"12345678",
		),
		nil,
	)
	req := NewAuthorizeRequest()

	err := s.parser.ParseAuthorizeRequest(context.Background(), r, req)
	s.Assert().Nil(err)

	s.Assert().NotEmpty(req.GetId())
	s.Assert().Equal(s.clientId, req.GetClient().GetId())
	s.Assert().Contains(req.GetResponseTypes(), spi.ResponseTypeCode)
	s.Assert().Equal("https://mock.test.org/callback", req.GetRedirectUri())
}
