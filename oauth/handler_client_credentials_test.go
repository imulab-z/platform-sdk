package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

func TestClientCredentialsHandler(t *testing.T) {
	s := new(ClientCredentialsHandlerTestSuite)
	suite.Run(t, s)
}

type ClientCredentialsHandlerTestSuite struct {
	suite.Suite
	h *ClientCredentialsHandler
}

func (s *ClientCredentialsHandlerTestSuite) SetupTest() {
	kid := "F4CC1518-A591-49E3-AEBD-0E71E1CA95B5"
	s.h = &ClientCredentialsHandler{
		ScopeStrategy: NewEqualScopeStrategy(),
		AccessTokenHelper: &AccessTokenHelper{
			Repo: &clientCredentialsHandlerTestSuiteAccessTokenRepo{},
			Strategy: NewRs256JwtAccessTokenStrategy(
				"test",
				30 * time.Minute,
				MustNewJwksWithRsaKeyForSigning(kid),
				kid,
			),
			Lifespan: 30 * time.Minute,
		},
		RefreshTokenHelper: &RefreshTokenHelper{
			Repo: &clientCredentialsHandlerTestSuiteRefreshTokenRepo{},
			Strategy: NewHmacShaRefreshTokenStrategy(32, MustHmacSha256Strategy()),
		},
	}
}

func (s *ClientCredentialsHandlerTestSuite) TestIssueToken() {
	req := NewTokenRequest()
	req.AddGrantTypes(spi.GrantTypeClient)
	req.AddScopes("foo")
	req.SetClient(&clientCredentialsHandlerTestSuiteClient{})
	req.SetRedirectUri("https://test.org/callback")

	resp := NewResponse()

	err := s.h.UpdateSession(context.Background(), req)
	s.Assert().Nil(err)

	err = s.h.IssueToken(context.Background(), req, resp)
	s.Assert().Nil(err)

	s.Assert().NotEmpty(resp.GetString(AccessToken))
	s.Assert().True(resp.Get(ExpiresIn).(int64) > 0)
	s.Assert().Equal("https://test.org/callback", resp.GetString(RedirectUri))
	s.Assert().Equal("Bearer", resp.GetString(TokenType))
}

type clientCredentialsHandlerTestSuiteAccessTokenRepo struct {
	*noOpAccessTokenRepo
}

type clientCredentialsHandlerTestSuiteRefreshTokenRepo struct {
	*noOpRefreshTokenRepo
}

type clientCredentialsHandlerTestSuiteClient struct {
	*panicClient
}

func (c *clientCredentialsHandlerTestSuiteClient) GetId() string {
	return "client/3b426761-9a41-4a73-a200-daed73879d41"
}

func (c *clientCredentialsHandlerTestSuiteClient) GetType() string {
	return spi.ClientTypeConfidential
}

func (c *clientCredentialsHandlerTestSuiteClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeClient}
}

func (c *clientCredentialsHandlerTestSuiteClient) GetScopes() []string {
	return []string{"foo", "bar"}
}