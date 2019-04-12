package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/imulab-z/platform-sdk/crypt"
	"github.com/imulab-z/platform-sdk/spi"
	"gopkg.in/square/go-jose.v2"
)

var (
	_ AccessTokenRepository = (*NoOpAccessTokenRepo)(nil)
	_ RefreshTokenRepository = (*NoOpRefreshTokenRepo)(nil)
	_ spi.OAuthClient = (*panicClient)(nil)
)

// AccessTokenRepository no-operation implementation
type NoOpAccessTokenRepo struct {}

func (r *NoOpAccessTokenRepo) Save(ctx context.Context, token string, req Request) error {
	return nil
}

func (r *NoOpAccessTokenRepo) GetRequest(ctx context.Context, token string) (Request, error) {
	return nil, nil
}

func (r *NoOpAccessTokenRepo) Delete(ctx context.Context, token string) error {
	return nil
}

func (r *NoOpAccessTokenRepo) DeleteByRequestId(ctx context.Context, requestId string) error {
	return nil
}

// RefreshTokenRepository no-operation implementation
type NoOpRefreshTokenRepo struct {}

func (r *NoOpRefreshTokenRepo) Save(ctx context.Context, token string, req Request) error {
	return nil
}

func (r *NoOpRefreshTokenRepo) GetRequest(ctx context.Context, token string) (Request, error) {
	return nil, nil
}

func (r *NoOpRefreshTokenRepo) Delete(ctx context.Context, token string) error {
	return nil
}

func (r *NoOpRefreshTokenRepo) DeleteByRequestId(ctx context.Context, requestId string) error {
	return nil
}

// OAuthClient panic implementation
type panicClient struct {}

func (c *panicClient) GetId() string {
	panic("implement GetId")
}

func (c *panicClient) GetName() string {
	panic("implement GetName")
}

func (c *panicClient) GetType() string {
	panic("implement GetType")
}

func (c *panicClient) GetRedirectUris() []string {
	panic("implement GetRedirectUris")
}

func (c *panicClient) GetResponseTypes() []string {
	panic("implement GetResponseTypes")
}

func (c *panicClient) GetGrantTypes() []string {
	panic("implement GetGrantTypes")
}

func (c *panicClient) GetScopes() []string {
	panic("implement GetScopes")
}

func MustNewJwksWithRsaKeyForSigning(kid string) *jose.JSONWebKeySet {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       privateKey,
				Algorithm: string(jose.RS256),
				Use:       "sign",
				KeyID:     kid,
			},
		},
	}
}

func MustHmacSha256Strategy() crypt.HmacShaStrategy {
	if b, err := crypt.RandomBytes(32); err != nil {
		panic(err)
	} else if s, err := crypt.NewHmacSha256Strategy(b); err != nil {
		panic(err)
	} else {
		return s
	}
}