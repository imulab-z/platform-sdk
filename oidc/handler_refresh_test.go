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

func TestRefreshHandler(t *testing.T) {
	s := new(RefreshHandlerTestSuite)
	suite.Run(t, s)
}

type RefreshHandlerTestSuite struct {
	suite.Suite
	h *RefreshHandler
}

func (s *RefreshHandlerTestSuite) SetupTest() {
	kid := "96665A88-AFB0-4D11-A555-6DFC560B530B"
	s.h = &RefreshHandler{
		IdTokenHelper: &IdTokenHelper{
			Strategy: &JwxIdTokenStrategy{
				Issuer:        "test",
				TokenLifespan: 24 * time.Hour,
				Jwks:          oauth.MustNewJwksWithRsaKeyForSigning(kid),
			},
		},
	}
}

func (s *RefreshHandlerTestSuite) TestIssueToken() {
	ctx := context.Background()

	req := NewTokenRequest()
	req.SetId(uuid.NewV4().String())
	req.SetRedirectUri("http://test.org/callback")
	req.AddGrantTypes(spi.GrantTypeRefresh)
	req.GetSession().AddGrantedScopes(spi.ScopeOpenId)
	req.SetClient(new(refreshHandlerTestSuiteClient))

	resp := oauth.NewResponse()

	err := s.h.UpdateSession(ctx, req)
	s.Assert().Nil(err)

	err = s.h.IssueToken(ctx, req, resp)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(resp.GetString(IdToken))
}

type refreshHandlerTestSuiteClient struct {
	*panicClient
}

func (c *refreshHandlerTestSuiteClient) GetId() string {
	return "AA628775-F1C4-49A7-9F12-98292B51381F"
}

func (c *refreshHandlerTestSuiteClient) GetRedirectUris() []string {
	return []string{"http://test.org/callback"}
}

func (c *refreshHandlerTestSuiteClient) GetResponseTypes() []string {
	return []string{spi.ResponseTypeToken, spi.ResponseTypeIdToken}
}

func (c *refreshHandlerTestSuiteClient) GetGrantTypes() []string {
	return []string{spi.GrantTypeImplicit}
}

func (c *refreshHandlerTestSuiteClient) GetScopes() []string {
	return []string{"foo", "bar", spi.ScopeOpenId, spi.ScopeOfflineAccess}
}

func (c *refreshHandlerTestSuiteClient) GetIdTokenSignedResponseAlg() string {
	return spi.SignAlgRS256
}

func (c *refreshHandlerTestSuiteClient) GetIdTokenEncryptedResponseAlg() string {
	return spi.EncryptAlgNone
}

func (c *refreshHandlerTestSuiteClient) GetIdTokenEncryptedResponseEnc() string {
	return spi.EncAlgNone
}
