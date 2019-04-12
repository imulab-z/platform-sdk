package oidc

import (
	"context"
	"errors"
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
)

var (
	_ oauth.AuthorizeCodeRepository = (*inMemAuthorizeCodeRepo)(nil)
	_ spi.OidcClient = (*panicClient)(nil)
)

// In memory implementation of oauth.AuthorizeCodeRepository
type inMemAuthorizeCodeRepo struct {
	store	map[string]oauth.AuthorizeRequest
}

func (r *inMemAuthorizeCodeRepo) GetRequest(ctx context.Context, code string) (oauth.AuthorizeRequest, error) {
	r.initStoreIfEmpty()
	if req, ok := r.store[code]; !ok {
		return nil, errors.New("request not found")
	} else {
		return req, nil
	}
}

func (r *inMemAuthorizeCodeRepo) Save(ctx context.Context, code string, req oauth.AuthorizeRequest) error {
	r.initStoreIfEmpty()
	r.store[code] = req
	return nil
}

func (r *inMemAuthorizeCodeRepo) Delete(ctx context.Context, code string) error {
	r.initStoreIfEmpty()
	delete(r.store, code)
	return nil
}

func (r *inMemAuthorizeCodeRepo) initStoreIfEmpty() {
	if r.store == nil {
		r.store = make(map[string]oauth.AuthorizeRequest)
	}
}

// All panic implementation of spi.OidcClient
type panicClient struct {}

func (c *panicClient) GetId() string {
	panic("implement me")
}

func (c *panicClient) GetName() string {
	panic("implement me")
}

func (c *panicClient) GetType() string {
	panic("implement me")
}

func (c *panicClient) GetRedirectUris() []string {
	panic("implement me")
}

func (c *panicClient) GetResponseTypes() []string {
	panic("implement me")
}

func (c *panicClient) GetGrantTypes() []string {
	panic("implement me")
}

func (c *panicClient) GetScopes() []string {
	panic("implement me")
}

func (c *panicClient) GetApplicationType() string {
	panic("implement me")
}

func (c *panicClient) GetContacts() string {
	panic("implement me")
}

func (c *panicClient) GetLogoUri() string {
	panic("implement me")
}

func (c *panicClient) GetClientUri() string {
	panic("implement me")
}

func (c *panicClient) GetPolicyUri() string {
	panic("implement me")
}

func (c *panicClient) GetTosUri() string {
	panic("implement me")
}

func (c *panicClient) GetJwksUri() string {
	panic("implement me")
}

func (c *panicClient) GetJwks() string {
	panic("implement me")
}

func (c *panicClient) GetSectorIdentifierUri() string {
	panic("implement me")
}

func (c *panicClient) GetSubjectType() string {
	panic("implement me")
}

func (c *panicClient) GetIdTokenSignedResponseAlg() string {
	panic("implement me")
}

func (c *panicClient) GetIdTokenEncryptedResponseAlg() string {
	panic("implement me")
}

func (c *panicClient) GetIdTokenEncryptedResponseEnc() string {
	panic("implement me")
}

func (c *panicClient) GetRequestObjectSigningAlg() string {
	panic("implement me")
}

func (c *panicClient) GetRequestObjectEncryptionAlg() string {
	panic("implement me")
}

func (c *panicClient) GetRequestObjectEncryptionEnc() string {
	panic("implement me")
}

func (c *panicClient) GetUserInfoSignedResponseAlg() string {
	panic("implement me")
}

func (c *panicClient) GetUserInfoEncryptedResponseAlg() string {
	panic("implement me")
}

func (c *panicClient) GetUserInfoEncryptedResponseEnc() string {
	panic("implement me")
}

func (c *panicClient) GetTokenEndpointAuthMethod() string {
	panic("implement me")
}

func (c *panicClient) GetTokenEndpointAuthSigningAlg() string {
	panic("implement me")
}

func (c *panicClient) GetDefaultMaxAge() uint64 {
	panic("implement me")
}

func (c *panicClient) IsAuthTimeRequired() bool {
	panic("implement me")
}

func (c *panicClient) GetDefaultAcrValues() []string {
	panic("implement me")
}

func (c *panicClient) GetInitiateLoginUri() string {
	panic("implement me")
}

func (c *panicClient) GetRequestUris() []string {
	panic("implement me")
}
