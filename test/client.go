package test

import (
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/mock"
)

type PanicClient struct {
	mock.Mock
}

func (c *PanicClient) GetId() string {
	panic("implement me")
}

func (c *PanicClient) GetName() string {
	panic("implement me")
}

func (c *PanicClient) GetType() string {
	panic("implement me")
}

func (c *PanicClient) GetRedirectUris() []string {
	panic("implement me")
}

func (c *PanicClient) GetResponseTypes() []string {
	panic("implement me")
}

func (c *PanicClient) GetGrantTypes() []string {
	panic("implement me")
}

func (c *PanicClient) GetScopes() []string {
	panic("implement me")
}

func (c *PanicClient) GetApplicationType() string {
	panic("implement me")
}

func (c *PanicClient) GetContacts() string {
	panic("implement me")
}

func (c *PanicClient) GetLogoUri() string {
	panic("implement me")
}

func (c *PanicClient) GetClientUri() string {
	panic("implement me")
}

func (c *PanicClient) GetPolicyUri() string {
	panic("implement me")
}

func (c *PanicClient) GetTosUri() string {
	panic("implement me")
}

func (c *PanicClient) GetJwksUri() string {
	panic("implement me")
}

func (c *PanicClient) GetJwks() string {
	panic("implement me")
}

func (c *PanicClient) GetSectorIdentifierUri() string {
	panic("implement me")
}

func (c *PanicClient) GetSubjectType() string {
	panic("implement me")
}

func (c *PanicClient) GetIdTokenSignedResponseAlg() string {
	panic("implement me")
}

func (c *PanicClient) GetIdTokenEncryptedResponseAlg() string {
	panic("implement me")
}

func (c *PanicClient) GetIdTokenEncryptedResponseEnc() string {
	panic("implement me")
}

func (c *PanicClient) GetRequestObjectSigningAlg() string {
	panic("implement me")
}

func (c *PanicClient) GetRequestObjectEncryptionAlg() string {
	panic("implement me")
}

func (c *PanicClient) GetRequestObjectEncryptionEnc() string {
	panic("implement me")
}

func (c *PanicClient) GetUserInfoSignedResponseAlg() string {
	panic("implement me")
}

func (c *PanicClient) GetUserInfoEncryptedResponseAlg() string {
	panic("implement me")
}

func (c *PanicClient) GetUserInfoEncryptedResponseEnc() string {
	panic("implement me")
}

func (c *PanicClient) GetTokenEndpointAuthMethod() string {
	panic("implement me")
}

func (c *PanicClient) GetTokenEndpointAuthSigningAlg() string {
	panic("implement me")
}

func (c *PanicClient) GetDefaultMaxAge() uint64 {
	panic("implement me")
}

func (c *PanicClient) IsAuthTimeRequired() bool {
	panic("implement me")
}

func (c *PanicClient) GetDefaultAcrValues() []string {
	panic("implement me")
}

func (c *PanicClient) GetInitiateLoginUri() string {
	panic("implement me")
}

func (c *PanicClient) GetRequestUris() []string {
	panic("implement me")
}

type MockClient struct {
	mock.Mock
	_id		string
}

func (c *MockClient) GetApplicationType() string {
	panic("implement me")
}

func (c *MockClient) GetContacts() string {
	panic("implement me")
}

func (c *MockClient) GetLogoUri() string {
	panic("implement me")
}

func (c *MockClient) GetClientUri() string {
	panic("implement me")
}

func (c *MockClient) GetPolicyUri() string {
	panic("implement me")
}

func (c *MockClient) GetTosUri() string {
	panic("implement me")
}

func (c *MockClient) GetJwksUri() string {
	panic("implement me")
}

func (c *MockClient) GetJwks() string {
	panic("implement me")
}

func (c *MockClient) GetSectorIdentifierUri() string {
	panic("implement me")
}

func (c *MockClient) GetSubjectType() string {
	panic("implement me")
}

func (c *MockClient) GetIdTokenSignedResponseAlg() string {
	panic("implement me")
}

func (c *MockClient) GetIdTokenEncryptedResponseAlg() string {
	panic("implement me")
}

func (c *MockClient) GetIdTokenEncryptedResponseEnc() string {
	panic("implement me")
}

func (c *MockClient) GetRequestObjectSigningAlg() string {
	panic("implement me")
}

func (c *MockClient) GetRequestObjectEncryptionAlg() string {
	panic("implement me")
}

func (c *MockClient) GetRequestObjectEncryptionEnc() string {
	panic("implement me")
}

func (c *MockClient) GetUserInfoSignedResponseAlg() string {
	panic("implement me")
}

func (c *MockClient) GetUserInfoEncryptedResponseAlg() string {
	panic("implement me")
}

func (c *MockClient) GetUserInfoEncryptedResponseEnc() string {
	panic("implement me")
}

func (c *MockClient) GetTokenEndpointAuthMethod() string {
	panic("implement me")
}

func (c *MockClient) GetTokenEndpointAuthSigningAlg() string {
	panic("implement me")
}

func (c *MockClient) GetDefaultMaxAge() uint64 {
	panic("implement me")
}

func (c *MockClient) IsAuthTimeRequired() bool {
	panic("implement me")
}

func (c *MockClient) GetDefaultAcrValues() []string {
	panic("implement me")
}

func (c *MockClient) GetInitiateLoginUri() string {
	panic("implement me")
}

func (c *MockClient) GetRequestUris() []string {
	panic("implement me")
}

func (c *MockClient) GetId() string {
	if len(c._id) == 0 {
		c._id = uuid.NewV4().String()
	}
	return c._id
}

func (c *MockClient) GetName() string {
	return "Mock Client"
}

func (c *MockClient) GetType() string {
	return spi.ClientTypeConfidential
}

func (c *MockClient) GetRedirectUris() []string {
	return []string{
		"https://mock.test.org/callback",
		"https://mock.test.org/callback2",
	}
}

func (c *MockClient) GetResponseTypes() []string {
	return []string{
		spi.ResponseTypeCode,
		spi.ResponseTypeToken,
	}
}

func (c *MockClient) GetGrantTypes() []string {
	return []string{
		spi.GrantTypeCode,
		spi.GrantTypeImplicit,
	}
}

func (c *MockClient) GetScopes() []string {
	return []string{
		"foo",
		"bar",
		spi.ScopeOfflineAccess,
	}
}
