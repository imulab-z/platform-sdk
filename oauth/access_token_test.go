package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/imulab-z/platform-sdk/test"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

func TestJwtAccessTokenStrategy(t *testing.T) {
	s := new(JwtAccessTokenStrategyTestSuite)
	suite.Run(t, s)
}

type JwtAccessTokenStrategyTestSuite struct {
	suite.Suite
	strategy *JwtAccessTokenStrategy
}

func (s *JwtAccessTokenStrategyTestSuite) SetupTest() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Assert().Nil(err)

	s.strategy = NewRs256JwtAccessTokenStrategy(
		"test",
		30*time.Minute,
		privateKey,
		privateKey.Public().(*rsa.PublicKey),
		"test-key",
	).(*JwtAccessTokenStrategy)
}

func (s *JwtAccessTokenStrategyTestSuite) TestNewToken() {
	req := NewAuthorizeRequest()
	req.setClient(new(test.MockClient))
	req.setSession(NewSession())

	tok, err := s.strategy.NewToken(context.Background(), req)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(tok)
}

func (s *JwtAccessTokenStrategyTestSuite) TestValidate() {
	req := NewAuthorizeRequest()
	req.setClient(new(test.MockClient))
	req.setSession(NewSession())

	tok, _ := s.strategy.NewToken(context.Background(), req)
	err := s.strategy.ValidateToken(context.Background(), tok, req)
	s.Assert().Nil(err)
}

func (s *JwtAccessTokenStrategyTestSuite) TestComputeIdentifier() {
	req := NewAuthorizeRequest()
	req.setClient(new(test.MockClient))
	req.setSession(NewSession())
	tok, _ := s.strategy.NewToken(context.Background(), req)

	id, err := s.strategy.ComputeIdentifier(tok)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(id)
}