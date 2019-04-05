package oauth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSelectRedirectUri(t *testing.T) {
	for _, v := range []struct{
		name 		string
		supplied	string
		registered	[]string
		expectUri	string
		expectErr	error
	}{
		{
			name: "select one out of two",
			supplied: "https://test.org/callback",
			registered: []string{
				"https://test.org/callback",
				"https://test.org/callback2",
			},
			expectUri: "https://test.org/callback",
			expectErr: nil,
		},
		{
			name: "default the only one registered",
			supplied: "",
			registered: []string{
				"https://test.org/callback",
			},
			expectUri: "https://test.org/callback",
			expectErr: nil,
		},
		{
			name: "supplied redirect_uri is not registered",
			supplied: "https://test.org/callback",
			registered: []string{
				"https://test.org/callback2",
				"https://test.org/callback3",
			},
			expectUri: "",
			expectErr: ErrNoRedirectUri,
		},
		{
			name: "default but multiple registered",
			supplied: "",
			registered: []string{
				"https://test.org/callback",
				"https://test.org/callback2",
			},
			expectUri: "",
			expectErr: ErrMultipleRedirectUri,
		},
	}{
		redirectUri, err := SelectRedirectUri(v.supplied, v.registered)
		if v.expectErr != nil {
			assert.Equal(t, v.expectErr, err, v.name)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, v.expectUri, redirectUri)
		}
	}
}
