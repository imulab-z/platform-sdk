package oauth

import "github.com/thoas/go-funk"

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
