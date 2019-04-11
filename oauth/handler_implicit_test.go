package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

func TestImplicitHandler(t *testing.T) {
	s := new(ImplicitHandlerTestSuite)
	suite.Run(t, s)
}

type ImplicitHandlerTestSuite struct {
	suite.Suite
	h 		*ImplicitHandler
}

func (s *ImplicitHandlerTestSuite) SetupTest() {
	kid := "127A6DD4-6692-45A9-8D9E-3AFAC7208BD9"
	s.h = &ImplicitHandler{
		AccessTokenHelper: &AccessTokenHelper{
			Lifespan: 30 * time.Minute,
			Repo: &implicitHandlerTestSuiteRepo{},
			Strategy: NewRs256JwtAccessTokenStrategy(
				"test",
				30 * time.Minute,
				MustNewJwksWithRsaKeyForSigning(kid),
				kid,
			),
		},
	}
}

func (s *ImplicitHandlerTestSuite) TestAuthorize() {
	req := NewAuthorizeRequest()
	req.SetClient(&implicitHandlerTestSuiteClient{})
	req.AddResponseTypes(spi.ResponseTypeToken)
	req.SetRedirectUri("https://test.org/callback")
	req.GetSession().AddGrantedScopes("foo", "bar")
	req.GetSession().SetSubject("test user")

	resp := NewResponse()

	err := s.h.Authorize(context.Background(), req, resp)
	s.Assert().Nil(err)

	s.Assert().NotEmpty(resp.GetString(AccessToken))
	s.Assert().Equal("Bearer", resp.GetString(TokenType))
	s.Assert().True(resp.Get(ExpiresIn).(int64) > 0)
}

type implicitHandlerTestSuiteRepo struct {
	*noOpAccessTokenRepo
}

type implicitHandlerTestSuiteClient struct {
	*panicClient
}

func (c *implicitHandlerTestSuiteClient) GetId() string {
	return "client/3b426761-9a41-4a73-a200-daed73879d41"
}

func (c *implicitHandlerTestSuiteClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeImplicit}
}