package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/crypt"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestHmacShaRefreshTokenStrategy(t *testing.T) {
	s := new(HmacShaRefreshTokenStrategyTestSuite)
	suite.Run(t, s)
}

type HmacShaRefreshTokenStrategyTestSuite struct {
	suite.Suite
	strategy 	*hmacShaRefreshTokenStrategy
}

func (s *HmacShaRefreshTokenStrategyTestSuite) SetupTest() {
	key, err := crypt.RandomBytes(32)
	s.Assert().Nil(err)

	hmac, err := crypt.NewHmacSha256Strategy(key)
	s.Assert().Nil(err)

	s.strategy = NewHmacShaRefreshTokenStrategy(32, hmac).(*hmacShaRefreshTokenStrategy)
}

func (s *HmacShaRefreshTokenStrategyTestSuite) TestNewCode() {
	code, err := s.strategy.NewToken(context.Background(), nil)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(code)
}

func (s *HmacShaRefreshTokenStrategyTestSuite) TestValidate() {
	code, _ := s.strategy.NewToken(context.Background(), nil)
	err := s.strategy.ValidateToken(context.Background(), code, nil)
	s.Assert().Nil(err)
}

func (s *HmacShaRefreshTokenStrategyTestSuite) TestComputeIdentifier() {
	code, _ := s.strategy.NewToken(context.Background(), nil)
	id, err := s.strategy.ComputeIdentifier(code)
	s.Assert().Nil(err)
	s.Assert().NotEmpty(id)
}
