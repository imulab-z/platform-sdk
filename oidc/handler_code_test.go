package oidc

import (
	"context"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

func TestAuthorizeCodeHandler(t *testing.T) {
	s := new(AuthorizeCodeHandlerTestSuite)
	suite.Run(t, s)
}

type AuthorizeCodeHandlerTestSuite struct {
	suite.Suite
	oauthHandler *oauth.AuthorizeCodeHandler
	oidcHandler  *AuthorizeCodeHandler
}

func (s *AuthorizeCodeHandlerTestSuite) SetupTest() {
	kid := "4ea0014d-9d5b-4cd2-ab81-b9897fed6da9"
	kid2 := "769fe165-8d54-408c-8c57-e359e75bd1fd"
	s.oauthHandler = &oauth.AuthorizeCodeHandler{
		ScopeComparator: oauth.EqualityComparator,
		CodeRepo:        newAuthorizeCodeHandlerTestSuiteAuthorizeCodeRepo(),
		CodeStrategy:    oauth.NewHmacShaAuthorizeCodeStrategy(16, oauth.MustHmacSha256Strategy()),
		AccessTokenHelper: &oauth.AccessTokenHelper{
			Repo: new(authorizeCodeHandlerTestSuiteAccessTokenRepo),
			Strategy: oauth.NewRs256JwtAccessTokenStrategy(
				"test",
				30*time.Minute,
				oauth.MustNewJwksWithRsaKeyForSigning(kid),
				kid,
			),
			Lifespan: 30 * time.Minute,
		},
		RefreshTokenHelper: &oauth.RefreshTokenHelper{
			Strategy: oauth.NewHmacShaRefreshTokenStrategy(32, oauth.MustHmacSha256Strategy()),
			Repo: new(authorizeCodeHandlerTestSuiteRefreshTokenRepo),
		},
	}
	s.oidcHandler = &AuthorizeCodeHandler{
		IdTokenHelper: &IdTokenHelper{
			Strategy: &JwxIdTokenStrategy{
				Issuer: "test",
				TokenLifespan: 24 * time.Hour,
				Jwks: oauth.MustNewJwksWithRsaKeyForSigning(kid2),
			},
		},
	}
}

func (s *AuthorizeCodeHandlerTestSuite) TestAuthorize() {
	ctx := context.Background()

	req := NewAuthorizeRequest()
	req.SetId(uuid.NewV4().String())
	req.AddResponseTypes(spi.ResponseTypeCode)
	req.AddScopes("foo", spi.ScopeOpenId)
	req.SetRedirectUri("http://test.org/callback")
	req.SetClient(new(authorizeCodeHandlerTestSuiteClient))
	req.GetSession().SetSubject("test user")
	req.GetSession().AddGrantedScopes("foo", spi.ScopeOpenId)
	req.GetSession().(Session).SetObfuscatedSubject("test user")

	resp := oauth.NewResponse()

	err := s.Authorize(ctx, req, resp)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(resp.GetString(oauth.Code))
}

func (s *AuthorizeCodeHandlerTestSuite) TestIssue() {
	ctx := context.Background()

	req := NewAuthorizeRequest()
	req.SetId(uuid.NewV4().String())
	req.AddResponseTypes(spi.ResponseTypeCode)
	req.AddScopes("foo", spi.ScopeOpenId)
	req.SetRedirectUri("http://test.org/callback")
	req.SetClient(new(authorizeCodeHandlerTestSuiteClient))
	req.GetSession().SetSubject("test user")
	req.GetSession().AddGrantedScopes("foo", spi.ScopeOpenId)
	req.GetSession().(Session).SetObfuscatedSubject("test user")

	resp := oauth.NewResponse()

	s.Require().Nil(s.Authorize(ctx, req, resp))
	s.Require().NotEmpty(resp.GetString(oauth.Code))

	code := resp.GetString(oauth.Code)
	req2 := NewTokenRequest()
	req2.SetId(uuid.NewV4().String())
	req2.SetCode(code)
	req2.SetRedirectUri("http://test.org/callback")
	req2.AddGrantTypes(spi.GrantTypeCode)
	req2.SetClient(new(authorizeCodeHandlerTestSuiteClient))

	resp2 := oauth.NewResponse()

	err := s.UpdateSession(ctx, req2)
	s.Assert().Nil(err)

	err = s.IssueToken(ctx, req2, resp2)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(resp2.GetString(oauth.AccessToken))
	s.Assert().Equal("Bearer", resp2.GetString(oauth.TokenType))
	s.Assert().True(resp2.Get(oauth.ExpiresIn).(int64) > 0)
	s.Assert().NotEmpty(resp2.GetString(IdToken))
}

func (s *AuthorizeCodeHandlerTestSuite) Authorize(ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error {
	if err := s.oauthHandler.Authorize(ctx, req, resp); err != nil {
		return err
	}

	if err := s.oidcHandler.Authorize(ctx, req, resp); err != nil {
		return err
	}

	return nil
}

func (s *AuthorizeCodeHandlerTestSuite) SupportsAuthorizeRequest(req oauth.AuthorizeRequest) bool {
	return true
}

func (s *AuthorizeCodeHandlerTestSuite) UpdateSession(ctx context.Context, req oauth.TokenRequest) error {
	if err := s.oauthHandler.UpdateSession(ctx, req); err != nil {
		return err
	}

	if err := s.oidcHandler.UpdateSession(ctx, req); err != nil {
		return err
	}

	return nil
}

func (s *AuthorizeCodeHandlerTestSuite) IssueToken(ctx context.Context, req oauth.TokenRequest, resp oauth.Response) error {
	if err := s.oauthHandler.IssueToken(ctx, req, resp); err != nil {
		return err
	}

	if err := s.oidcHandler.IssueToken(ctx, req, resp); err != nil {
		return err
	}

	return nil
}

func (s *AuthorizeCodeHandlerTestSuite) SupportsTokenRequest(req oauth.TokenRequest) bool {
	return true
}

func newAuthorizeCodeHandlerTestSuiteAuthorizeCodeRepo() oauth.AuthorizeCodeRepository {
	return &authorizeCodeHandlerTestSuiteAuthorizeCodeRepo {
		inMemAuthorizeCodeRepo: &inMemAuthorizeCodeRepo{
			store: make(map[string]oauth.AuthorizeRequest),
		},
	}
}

type authorizeCodeHandlerTestSuiteAuthorizeCodeRepo struct {
	*inMemAuthorizeCodeRepo
}

type authorizeCodeHandlerTestSuiteAccessTokenRepo struct {
	*oauth.NoOpAccessTokenRepo
}

type authorizeCodeHandlerTestSuiteRefreshTokenRepo struct {
	*oauth.NoOpRefreshTokenRepo
}

type authorizeCodeHandlerTestSuiteClient struct {
	*panicClient
}

func (c *authorizeCodeHandlerTestSuiteClient) GetId() string {
	return "AA628775-F1C4-49A7-9F12-98292B51381F"
}

func (c *authorizeCodeHandlerTestSuiteClient) GetRedirectUris() []string {
	return []string{"http://test.org/callback"}
}

func (c *authorizeCodeHandlerTestSuiteClient) GetResponseTypes() []string {
	return []string{spi.ResponseTypeCode}
}

func (c *authorizeCodeHandlerTestSuiteClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeCode}
}

func (c *authorizeCodeHandlerTestSuiteClient) GetScopes() []string {
	return []string{"foo", "bar", spi.ScopeOpenId, spi.ScopeOfflineAccess}
}

func (c *authorizeCodeHandlerTestSuiteClient) GetIdTokenSignedResponseAlg() string {
	return spi.SignAlgRS256
}

func (c *authorizeCodeHandlerTestSuiteClient) GetIdTokenEncryptedResponseAlg() string {
	return spi.EncryptAlgNone
}

func (c *authorizeCodeHandlerTestSuiteClient) GetIdTokenEncryptedResponseEnc() string {
	return spi.EncAlgNone
}