package crypt

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestHmacSha256Strategy(t *testing.T) {
	suite.Run(t, &HmacShaStrategyTestSuite{keyLen:32})
}

func TestHmacSha384Strategy(t *testing.T) {
	suite.Run(t, &HmacShaStrategyTestSuite{keyLen:48})
}

func TestHmacSha512Strategy(t *testing.T) {
	suite.Run(t, &HmacShaStrategyTestSuite{keyLen:64})
}

type HmacShaStrategyTestSuite struct {
	suite.Suite
	keyLen		uint
}

func (s *HmacShaStrategyTestSuite) createStrategy() HmacShaStrategy {
	var (
		key 		[]byte
		strategy	HmacShaStrategy
		err 		error
	)

	key, err = RandomBytes(s.keyLen)
	if err != nil {
		s.FailNow("Cannot generate random key")
	}

	switch s.keyLen {
	case 32:
		strategy, err = NewHmacSha256Strategy(key)
	case 48:
		strategy, err = NewHmacSha384Strategy(key)
	case 64:
		strategy, err = NewHmacSha512Strategy(key)
	default:
		panic("unsupported key length")
	}

	if err != nil || strategy == nil {
		s.FailNow("Cannot create hmac-sha strategy")
	}

	return strategy
}

func (s *HmacShaStrategyTestSuite) TestGenerate() {
	var (
		err	error
	)

	strategy := s.createStrategy()
	key, sig, err := strategy.Generate(16)

	s.Assert().Nil(err)
	s.Assert().NotEmpty(key)
	s.Assert().NotEmpty(sig)

	rawKey, err := b64.DecodeString(key)
	s.Assert().Nil(err)
	s.Assert().Len(rawKey, 16)

	rawSig, err := b64.DecodeString(sig)
	s.Assert().Nil(err)
	s.Assert().Len(rawSig, int(s.keyLen))
}

func (s *HmacShaStrategyTestSuite) TestVerify() {
	var (
		err	error
	)

	strategy := s.createStrategy()
	key1, sig1, err := strategy.Generate(16)
	s.Assert().Nil(err)
	key2, sig2, err := strategy.Generate(16)
	s.Assert().Nil(err)

	err = strategy.Verify(key1, sig1)
	s.Assert().Nil(err)

	err = strategy.Verify(key2, sig2)
	s.Assert().Nil(err)

	err = strategy.Verify(key1, sig2)
	s.Assert().Equal(errSignatureMismatch, err)

	err = strategy.Verify(key2, sig1)
	s.Assert().Equal(errSignatureMismatch, err)
}
