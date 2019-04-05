package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/crypt"
	"github.com/imulab-z/platform-sdk/spi"
	"strings"
)

type RefreshTokenStrategy interface {
	ComputeIdentifier(token string) (string, error)
	NewToken(ctx context.Context, req Request) (string, error)
	ValidateToken(ctx context.Context, token string, req Request) error
}

type RefreshTokenRepository interface {
	Save(ctx context.Context, token string, req Request) error
	GetSession(ctx context.Context, token string) (Session, error)
	Delete(ctx context.Context, token string) error
}

func NewHmacShaRefreshTokenStrategy(entropy uint, hmac crypt.HmacShaStrategy) RefreshTokenStrategy {
	return &hmacShaRefreshTokenStrategy{entropy: entropy, hmac: hmac}
}

type hmacShaRefreshTokenStrategy struct {
	entropy 	uint
	hmac		crypt.HmacShaStrategy
}

func (s *hmacShaRefreshTokenStrategy) ComputeIdentifier(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", spi.ErrInvalidGrant("refresh token is invalid.")
	}
	return parts[1], nil
}

func (s *hmacShaRefreshTokenStrategy) NewToken(ctx context.Context, req Request) (string, error) {
	if key, sig, err := s.hmac.Generate(s.entropy); err != nil {
		return "", spi.ErrServerError(err)
	} else {
		return key + "." + sig, nil
	}
}

func (s *hmacShaRefreshTokenStrategy) ValidateToken(ctx context.Context, token string, req Request) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return spi.ErrInvalidGrant("refresh token is invalid.")
	} else if err := s.hmac.Verify(parts[0], parts[1]); err != nil {
		return spi.ErrInvalidGrant("refresh token failed to pass verification.")
	}
	return nil
}

