package oauth

import (
	"github.com/imulab-z/platform-sdk/test"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestEqualScopeStrategy(t *testing.T) {
	s := new(EqualScopeStrategyTestSuite)
	suite.Run(t, s)
}

type EqualScopeStrategyTestSuite struct {
	suite.Suite
	strategy 	*equalScopeStrategy
}

func (s *EqualScopeStrategyTestSuite) SetupTest() {
	s.strategy = NewEqualScopeStrategy().(*equalScopeStrategy)
}

func (s *EqualScopeStrategyTestSuite) TestAccepts() {
	client := new(test.MockClient)
	s.Assert().True(s.strategy.Accepts(client, "foo"))
	s.Assert().False(s.strategy.Accepts(client, "invalid"))
}

func (s *EqualScopeStrategyTestSuite) TestAcceptAll() {
	client := new(test.MockClient)
	s.Assert().True(s.strategy.AcceptsAll(client, []string{"foo", "bar"}))
	s.Assert().False(s.strategy.AcceptsAll(client, []string{"foo", "invalid"}))
}
