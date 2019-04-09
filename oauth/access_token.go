package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

type AccessTokenStrategy interface {
	ComputeIdentifier(token string) (string, error)
	NewToken(ctx context.Context, req Request) (string, error)
	ValidateToken(ctx context.Context, token string, req Request) error
}

type AccessTokenRepository interface {
	Save(ctx context.Context, token string, req Request) error
	GetSession(ctx context.Context, token string) (Session, error)
	Delete(ctx context.Context, token string) error
}

func NewRs256JwtAccessTokenStrategy(
	issuer string,
	tokenLifespan time.Duration,
	jwks *jose.JSONWebKeySet,
	keyId string,
) AccessTokenStrategy {
	return &JwtAccessTokenStrategy{
		Issuer:        issuer,
		TokenLifespan: tokenLifespan,
		SigningAlg:    jose.RS256,
		Jwks:          jwks,
		KeyId:         keyId,
	}
}

type JwtAccessTokenStrategy struct {
	Issuer        string
	TokenLifespan time.Duration
	SigningAlg    jose.SignatureAlgorithm
	Jwks    *jose.JSONWebKeySet
	KeyId   string
	_signer jose.Signer
}

func (s *JwtAccessTokenStrategy) ComputeIdentifier(token string) (string, error) {
	out := jwt.Claims{}

	if tok, err := jwt.ParseSigned(token); err != nil {
		return "", err
	} else if err := tok.UnsafeClaimsWithoutVerification(&out); err != nil {
		return "", err
	} else if len(out.ID) == 0 {
		return "", spi.ErrInvalidGrant("access token has no encoded id.")
	}

	return out.ID, nil
}

func (s *JwtAccessTokenStrategy) NewToken(ctx context.Context, req Request) (string, error) {
	return jwt.Signed(s.mustSigner()).
		Claims(&jwt.Claims{
			ID:        uuid.NewV4().String(),
			Issuer:    s.Issuer,
			Subject:   req.GetSession().GetSubject(),
			Audience:  []string{req.GetClient().GetId()},
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Expiry:    jwt.NewNumericDate(time.Now().Add(s.TokenLifespan)),
		}).
		Claims(req.GetSession().GetAccessClaims()).
		CompactSerialize()
}

func (s *JwtAccessTokenStrategy) ValidateToken(ctx context.Context, token string, req Request) error {
	out := jwt.Claims{}

	if tok, err := jwt.ParseSigned(token); err != nil {
		return err
	} else if err := tok.Claims(FindVerificationKeyById(s.Jwks, s.KeyId), &out); err != nil {
		return err
	} else if err := out.ValidateWithLeeway(jwt.Expected{
		Issuer:   s.Issuer,
		Audience: []string{req.GetClient().GetId()},
	}, 5*time.Second); err != nil {
		return err
	}

	return nil
}

func (s *JwtAccessTokenStrategy) mustSigner() jose.Signer {
	if s._signer != nil {
		return s._signer
	}

	opt := (&jose.SignerOptions{}).WithType("JWT")

	if signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: s.SigningAlg,
		Key:       FindSigningKeyById(s.Jwks, s.KeyId),
	}, opt); err != nil {
		panic("failed to create jwt signer")
	} else {
		s._signer = signer
	}

	return s._signer
}

type AccessTokenHelper struct {
	Strategy AccessTokenStrategy
	Repo     AccessTokenRepository
	Lifespan time.Duration
}

func (h *AccessTokenHelper) GenToken(ctx context.Context, req Request, resp Response) error {
	if tok, err := h.Strategy.NewToken(ctx, req); err != nil {
		return err
	} else {
		go func() {
			if err := h.Repo.Save(context.Background(), tok, req); err != nil {
				logrus.WithFields(logrus.Fields{
					"error":      err,
					"token":      tok,
					"request_id": req.GetId(),
					"client_id":  req.GetClient().GetId(),
				}).Errorln("failed to save access token.")
			}
		}()
		resp.Set(RParamAccessToken, tok)
		resp.Set(RParamTokenType, "Bearer")
		resp.Set(RParamExpiresIn, h.Lifespan.Nanoseconds() / int64(time.Second))
		return nil
	}
}