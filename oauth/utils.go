package oauth

import "github.com/thoas/go-funk"

// Returns true if the array contains exactly the said string element.
func Exactly(array []string, str string) bool {
	return len(array) == 1 &&
		funk.ContainsString(array, str)
}
