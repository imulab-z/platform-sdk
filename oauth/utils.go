package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
	"sync"
)

// todo phase out
// Returns true if the array contains exactly the said elements.
func Exactly(array []string, elements ...string) bool {
	if len(array) != len(elements) {
		return false
	}
	for _, e := range elements {
		if !funk.ContainsString(array, e) {
			return false
		}
	}
	return true
}

// internal helper method to perform a error-capable action asynchronously
func doAsync(ctx context.Context, wg *sync.WaitGroup, errChan chan error, action func() error) {
	go func() {
		defer wg.Done()
		if err := action(); err != nil {
			select {
			case <-ctx.Done():
				return
			case errChan <- err:
				return
			default:
				return
			}
		}
	}()
}

// Returns true when the registered scopes of the client associated with the request accepts all the granted scopes
// within the request session; false otherwise.
// Comparison is made based on the supplied comparator, when nil, defaults to EqualityComparator.
func ClientAcceptsGrantedScopes(req Request, comparator Comparator) bool {
	if comparator == nil {
		comparator = EqualityComparator
	}
	return V(req.GetClient().GetScopes()).ContainsByComparator(req.GetSession().GetGrantedScopes(), comparator)
}

// Returns true when the registered scopes of the client associated with the request accepts all requested scopes.
// Otherwise returns false.
// Comparison is made based on the supplied comparator, when nil, defaults to EqualityComparator.
func ClientAcceptsScopes(req Request, comparator Comparator) bool {
	if comparator == nil {
		comparator = EqualityComparator
	}
	return V(req.GetClient().GetScopes()).ContainsByComparator(req.GetScopes(), comparator)
}

// Returns true when the client's registered response types contains the queried response type; false otherwise.
func ClientRegisteredResponseType(client spi.OAuthClient, responseType string) bool {
	return funk.ContainsString(client.GetResponseTypes(), responseType)
}

// Returns true when the client's registered grant types contains the queried grant type; false otherwise.
func ClientRegisteredGrantType(client spi.OAuthClient, grantType string) bool {
	return funk.ContainsString(client.GetGrantTypes(), grantType)
}