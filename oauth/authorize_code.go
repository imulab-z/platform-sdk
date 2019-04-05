package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/crypt"
	"github.com/imulab-z/platform-sdk/spi"
	"strings"
)

type AuthorizeCodeStrategy interface {
	// Computes its identifier for storage purpose
	ComputeIdentifier(code string) (string, error)
	// Generate a new code.
	NewCode(ctx context.Context, req AuthorizeRequest) (string, error)
	// Validate the given authorize code, update session information, if necessary
	ValidateCode(ctx context.Context, code string, req AuthorizeRequest) error
}

type AuthorizeCodeRepository interface {
	// Find the associated session with the authorization code
	GetSession(ctx context.Context, code string) (Session, error)
	// Interface for managing persistence of authorization code
	// Persist the authorize code and associate it with the request session
	Save(ctx context.Context, code string, req AuthorizeRequest) error
	// Remove the authorize code from persistence
	Delete(ctx context.Context, code string) error
}

func NewHmacShaAuthorizeCodeStrategy(entropy uint, hmac crypt.HmacShaStrategy) AuthorizeCodeStrategy {
	return &hmacShaAuthorizeCodeStrategy{entropy: entropy, hmac: hmac}
}

type hmacShaAuthorizeCodeStrategy struct {
	entropy 	uint
	hmac		crypt.HmacShaStrategy
}

func (s *hmacShaAuthorizeCodeStrategy) ComputeIdentifier(code string) (string, error) {
	parts := strings.Split(code, ".")
	if len(parts) != 2 {
		return "", spi.ErrInvalidGrant("authorize code is invalid.")
	}
	return parts[1], nil
}

func (s *hmacShaAuthorizeCodeStrategy) NewCode(ctx context.Context, req AuthorizeRequest) (string, error) {
	if key, sig, err := s.hmac.Generate(s.entropy); err != nil {
		return "", spi.ErrServerError(err)
	} else {
		return key + "." + sig, nil
	}
}

func (s *hmacShaAuthorizeCodeStrategy) ValidateCode(ctx context.Context, code string, req AuthorizeRequest) error {
	parts := strings.Split(code, ".")
	if len(parts) != 2 {
		return spi.ErrInvalidGrant("authorize code is invalid.")
	} else if err := s.hmac.Verify(parts[0], parts[1]); err != nil {
		return spi.ErrInvalidGrant("authorize code failed to pass verification.")
	}
	return nil
}


