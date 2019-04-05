package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/crypt"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestHmacShaAuthorizeCodeStrategy(t *testing.T) {
	s := new(HmacShaAuthorizeCodeStrategyTestSuite)
	suite.Run(t, s)
}

type HmacShaAuthorizeCodeStrategyTestSuite struct {
	suite.Suite
	strategy 	*hmacShaAuthorizeCodeStrategy
}

func (s *HmacShaAuthorizeCodeStrategyTestSuite) SetupTest() {
	key, err := crypt.RandomBytes(32)
	s.Assert().Nil(err)

	hmac, err := crypt.NewHmacSha256Strategy(key)
	s.Assert().Nil(err)

	s.strategy = NewHmacShaAuthorizeCodeStrategy(32, hmac).(*hmacShaAuthorizeCodeStrategy)
}

func (s *HmacShaAuthorizeCodeStrategyTestSuite) TestNewCode() {
	code, err := s.strategy.NewCode(context.Background(), nil)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(code)
}

func (s *HmacShaAuthorizeCodeStrategyTestSuite) TestValidate() {
	code, _ := s.strategy.NewCode(context.Background(), nil)
	err := s.strategy.ValidateCode(context.Background(), code, nil)
	s.Assert().Nil(err)
}

func (s *HmacShaAuthorizeCodeStrategyTestSuite) TestComputeIdentifier() {
	code, _ := s.strategy.NewCode(context.Background(), nil)
	id, err := s.strategy.ComputeIdentifier(code)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(id)
}