package test

import (
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
	_id		string
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
