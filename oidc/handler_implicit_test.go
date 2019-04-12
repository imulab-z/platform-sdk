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

func TestImplicitHandler(t *testing.T) {
	s := new(ImplicitHandlerTestSuite)
	suite.Run(t, s)
}

type ImplicitHandlerTestSuite struct {
	suite.Suite
	h *ImplicitHandler
}

func (s *ImplicitHandlerTestSuite) SetupTest() {
	kid := "5E3A6403-0102-4463-B212-54AD290A8685"
	kid2 := "C53B093B-3130-4657-8131-B0F53D17F4BA"
	s.h = &ImplicitHandler{
		AccessTokenHelper: &oauth.AccessTokenHelper{
			Repo: new(implicitHandlerTestSuiteAccessTokenRepo),
			Strategy: oauth.NewRs256JwtAccessTokenStrategy(
				"test",
				30*time.Minute,
				oauth.MustNewJwksWithRsaKeyForSigning(kid),
				kid,
			),
			Lifespan: 30 * time.Minute,
		},
		IdTokenHelper: &IdTokenHelper{
			Strategy: &JwxIdTokenStrategy{
				Issuer: "test",
				TokenLifespan: 24 * time.Hour,
				Jwks: oauth.MustNewJwksWithRsaKeyForSigning(kid2),
			},
		},
	}
}

func (s *ImplicitHandlerTestSuite) TestAuthorize() {
	ctx := context.Background()

	req := NewAuthorizeRequest()
	req.SetId(uuid.NewV4().String())
	req.AddResponseTypes(spi.ResponseTypeToken, spi.ResponseTypeIdToken)
	req.AddScopes("foo", spi.ScopeOpenId)
	req.SetRedirectUri("http://test.org/callback")
	req.SetClient(new(implicitHandlerTestSuiteClient))
	req.GetSession().SetSubject("test user")
	req.GetSession().AddGrantedScopes("foo", spi.ScopeOpenId)
	req.GetSession().(Session).SetObfuscatedSubject("test user")

	resp := oauth.NewResponse()

	err := s.h.Authorize(ctx, req, resp)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(resp.GetString(oauth.AccessToken))
	s.Assert().NotEmpty(resp.GetString(IdToken))
}

type implicitHandlerTestSuiteAccessTokenRepo struct {
	*oauth.NoOpAccessTokenRepo
}

type implicitHandlerTestSuiteClient struct {
	*panicClient
}

func (c *implicitHandlerTestSuiteClient) GetId() string {
	return "AA628775-F1C4-49A7-9F12-98292B51381F"
}

func (c *implicitHandlerTestSuiteClient) GetRedirectUris() []string {
	return []string{"http://test.org/callback"}
}

func (c *implicitHandlerTestSuiteClient) GetResponseTypes() []string {
	return []string{spi.ResponseTypeToken, spi.ResponseTypeIdToken}
}

func (c *implicitHandlerTestSuiteClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeImplicit}
}

func (c *implicitHandlerTestSuiteClient) GetScopes() []string {
	return []string{"foo", "bar", spi.ScopeOpenId, spi.ScopeOfflineAccess}
}

func (c *implicitHandlerTestSuiteClient) GetIdTokenSignedResponseAlg() string {
	return spi.SignAlgRS256
}

func (c *implicitHandlerTestSuiteClient) GetIdTokenEncryptedResponseAlg() string {
	return spi.EncryptAlgNone
}

func (c *implicitHandlerTestSuiteClient) GetIdTokenEncryptedResponseEnc() string {
	return spi.EncAlgNone
}