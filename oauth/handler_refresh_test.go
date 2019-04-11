package oauth

import (
	"context"
	"fmt"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

func TestRefreshHandler(t *testing.T) {
	s := new(RefreshHandlerTestSuite)
	suite.Run(t, s)
}

type RefreshHandlerTestSuite struct {
	suite.Suite
	h 	*RefreshHandler
}

func (s *RefreshHandlerTestSuite) SetupTest() {
	kid := "F4CC1518-A591-49E3-AEBD-0E71E1CA95B5"
	accessRepo := &refreshHandlerTestSuiteAccessTokenRepo{}
	refreshRepo := &refreshHandlerTestSuiteRefreshTokenRepo{}
	refreshStrategy := NewHmacShaRefreshTokenStrategy(32, MustHmacSha256Strategy())
	s.h = &RefreshHandler{
		AccessTokenHelper: &AccessTokenHelper{
			Lifespan: 30 * time.Minute,
			Repo: accessRepo,
			Strategy: NewRs256JwtAccessTokenStrategy(
				"test",
				30 * time.Minute,
				MustNewJwksWithRsaKeyForSigning(kid),
				kid,
			),
		},
		RefreshTokenHelper: &RefreshTokenHelper{
			Repo: refreshRepo,
			Strategy: refreshStrategy,
		},
		AccessTokenRepo: accessRepo,
		RefreshTokenRepo: refreshRepo,
		RefreshTokenStrategy: refreshStrategy,
	}
}

func (s *RefreshHandlerTestSuite) TestRefreshToken() {
	refreshToken, err := s.h.RefreshTokenStrategy.NewToken(context.Background(), nil)
	s.Require().Nil(err)

	req := NewTokenRequest()
	req.SetRedirectUri("https://test.org/callback")
	req.SetClient(&refreshHandlerTestSuiteClient{})
	req.AddGrantTypes(spi.GrantTypeRefresh)
	req.SetRefreshToken(refreshToken)

	resp := NewResponse()

	err = s.h.UpdateSession(context.Background(), req)
	s.Assert().Nil(err)

	err = s.h.IssueToken(context.Background(), req, resp)
	s.Assert().Nil(err)

	s.Assert().Equal("Bearer", resp.GetString(TokenType))
	s.Assert().True(resp.Get(ExpiresIn).(int64) > 0)
	s.Assert().NotEmpty(resp.GetString(RefreshToken))
	s.Assert().NotEmpty(resp.GetString(AccessToken))
}

// support: AccessTokenRepository
type refreshHandlerTestSuiteAccessTokenRepo struct {
	*noOpAccessTokenRepo
}

func (r *refreshHandlerTestSuiteAccessTokenRepo) DeleteByRequestId(ctx context.Context, requestId string) error {
	fmt.Printf("deleted access token with request id %s\n", requestId)
	return nil
}

// support: RefreshTokenRepository
type refreshHandlerTestSuiteRefreshTokenRepo struct {
	*noOpRefreshTokenRepo
}

func (r *refreshHandlerTestSuiteRefreshTokenRepo) GetRequest(ctx context.Context, token string) (Request, error) {
	req := NewTokenRequest()
	req.SetId("old_request")
	req.GetSession().SetSubject("test user")
	req.GetSession().AddGrantedScopes("foo", "bar")
	return req, nil
}

func (r *refreshHandlerTestSuiteRefreshTokenRepo) DeleteByRequestId(ctx context.Context, requestId string) error {
	fmt.Printf("deleted refresh token with request id %s\n", requestId)
	return nil
}

// support: OAuthClient
type refreshHandlerTestSuiteClient struct {
	*panicClient
}

func (c *refreshHandlerTestSuiteClient) GetId() string {
	return "client/3b426761-9a41-4a73-a200-daed73879d41"
}

func (c *refreshHandlerTestSuiteClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeRefresh}
}