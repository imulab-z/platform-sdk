package test

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/stretchr/testify/mock"
)

type MockClientLookup struct {
	mock.Mock
}

func (m *MockClientLookup) FindById(ctx context.Context, id string) (spi.OidcClient, error) {
	args := m.Called(id)
	return args.Get(0).(spi.OidcClient), args.Error(1)
}

