package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/crypt"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/imulab-z/platform-sdk/test"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestAuthorizeCodeHandler(t *testing.T) {
	s := new(AuthorizeCodeHandlerTestSuite)
	suite.Run(t, s)
}

type AuthorizeCodeHandlerTestSuite struct {
	suite.Suite
	h 	*AuthorizeCodeHandler
}

func (s *AuthorizeCodeHandlerTestSuite) SetupTest() {
	codeRepo := &noOpAuthorizeCodeRepository{}

	signingKey, err := crypt.RandomBytes(32)
	s.Assert().Nil(err)
	hmac, err := crypt.NewHmacSha256Strategy(signingKey)
	s.Assert().Nil(err)
	codeStrategy := NewHmacShaAuthorizeCodeStrategy(32, hmac)

	s.h = &AuthorizeCodeHandler{
		CodeRepo: codeRepo,
		CodeStrategy: codeStrategy,
		ScopeComparator: EqualityComparator,
	}
}

func (s *AuthorizeCodeHandlerTestSuite) TestAuthorize() {
	client := new(test.MockClient)

	req := NewAuthorizeRequest()
	req.AddResponseTypes(spi.ResponseTypeCode)
	req.SetClient(client)
	req.SetRedirectUri(client.GetRedirectUris()[0])
	req.SetState("12345")

	resp := NewResponse()

	err := s.h.Authorize(context.Background(), req, resp)
	s.Assert().Nil(err)

	s.Assert().NotEmpty(resp.GetString(Code))
}

type noOpAuthorizeCodeRepository struct {}

func (_ *noOpAuthorizeCodeRepository) GetRequest(ctx context.Context, code string) (AuthorizeRequest, error) {
	return nil, nil
}

func (_ *noOpAuthorizeCodeRepository) Save(ctx context.Context, code string, req AuthorizeRequest) error {
	return nil
}

func (_ *noOpAuthorizeCodeRepository) Delete(ctx context.Context, code string) error {
	return nil
}


