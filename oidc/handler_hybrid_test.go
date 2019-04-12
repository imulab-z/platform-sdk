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

func TestHybridHandler(t *testing.T) {
	s := new(HybridHandlerTestSuite)
	suite.Run(t, s)
}

type HybridHandlerTestSuite struct {
	suite.Suite
	h0 *oauth.AuthorizeCodeHandler
	h1 *HybridHandler
}

func (s *HybridHandlerTestSuite) SetupTest() {
	kid := "093421FE-C657-46D8-8B9E-A903E375A57F"
	kid2 := "5AE51705-A44A-4D76-9E59-256F3A1E8A79"
	idTokenHelper := &IdTokenHelper{
		Strategy: &JwxIdTokenStrategy{
			Issuer: "test",
			TokenLifespan: 24 * time.Hour,
			Jwks: oauth.MustNewJwksWithRsaKeyForSigning(kid2),
		},
	}
	s.h0 = &oauth.AuthorizeCodeHandler{
		ScopeComparator: oauth.EqualityComparator,
		CodeRepo:        newAuthorizeCodeHandlerTestSuiteAuthorizeCodeRepo(),
		CodeStrategy:    oauth.NewHmacShaAuthorizeCodeStrategy(16, oauth.MustHmacSha256Strategy()),
		AccessTokenHelper: &oauth.AccessTokenHelper{
			Repo: new(hybridHandlerTestSuiteAccessTokenRepo),
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
			Repo: new(hybridHandlerTestSuiteRefreshTokenRepo),
		},
	}
	s.h1 = &HybridHandler{
		AuthorizeCodeHandler: &AuthorizeCodeHandler{
			IdTokenHelper: idTokenHelper,
		},
		IdTokenHelper: idTokenHelper,
		AccessTokenHelper: &oauth.AccessTokenHelper{
			Repo: new(hybridHandlerTestSuiteAccessTokenRepo),
			Strategy: oauth.NewRs256JwtAccessTokenStrategy(
				"test",
				30*time.Minute,
				oauth.MustNewJwksWithRsaKeyForSigning(kid),
				kid,
			),
			Lifespan: 30 * time.Minute,
		},
	}
}

func (s *HybridHandlerTestSuite) TestAuthorize() {
	ctx := context.Background()

	req := NewAuthorizeRequest()
	req.SetId(uuid.NewV4().String())
	req.AddResponseTypes(spi.ResponseTypeCode, spi.ResponseTypeToken, spi.ResponseTypeIdToken)
	req.AddScopes("foo", spi.ScopeOpenId)
	req.SetRedirectUri("http://test.org/callback")
	req.SetClient(new(hybridHandlerTestSuiteClient))
	req.GetSession().SetSubject("test user")
	req.GetSession().AddGrantedScopes("foo", spi.ScopeOpenId)
	req.GetSession().(Session).SetObfuscatedSubject("test user")

	resp := oauth.NewResponse()

	err := s.Authorize(ctx, req, resp)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(resp.GetString(oauth.Code))
	s.Assert().NotEmpty(resp.GetString(oauth.AccessToken))
	s.Assert().NotEmpty(resp.GetString(IdToken))
}

func (s *HybridHandlerTestSuite) Authorize(ctx context.Context, req oauth.AuthorizeRequest, resp oauth.Response) error {
	if err := s.h0.Authorize(ctx, req, resp); err != nil {
		return err
	}

	if err := s.h1.Authorize(ctx, req, resp); err != nil {
		return err
	}

	return nil
}

func (s *HybridHandlerTestSuite) SupportsAuthorizeRequest(req oauth.AuthorizeRequest) bool {
	return true
}

type hybridHandlerTestSuiteAccessTokenRepo struct {
	*oauth.NoOpAccessTokenRepo
}

type hybridHandlerTestSuiteRefreshTokenRepo struct {
	*oauth.NoOpRefreshTokenRepo
}

type hybridHandlerTestSuiteClient struct {
	*panicClient
}

func (c *hybridHandlerTestSuiteClient) GetId() string {
	return "AA628775-F1C4-49A7-9F12-98292B51381F"
}

func (c *hybridHandlerTestSuiteClient) GetRedirectUris() []string {
	return []string{"http://test.org/callback"}
}

func (c *hybridHandlerTestSuiteClient) GetResponseTypes() []string {
	return []string{spi.ResponseTypeCode, spi.ResponseTypeToken, spi.ResponseTypeIdToken}
}

func (c *hybridHandlerTestSuiteClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeCode, spi.GrantTypeImplicit}
}

func (c *hybridHandlerTestSuiteClient) GetScopes() []string {
	return []string{"foo", "bar", spi.ScopeOpenId, spi.ScopeOfflineAccess}
}

func (c *hybridHandlerTestSuiteClient) GetIdTokenSignedResponseAlg() string {
	return spi.SignAlgRS256
}

func (c *hybridHandlerTestSuiteClient) GetIdTokenEncryptedResponseAlg() string {
	return spi.EncryptAlgNone
}

func (c *hybridHandlerTestSuiteClient) GetIdTokenEncryptedResponseEnc() string {
	return spi.EncAlgNone
}