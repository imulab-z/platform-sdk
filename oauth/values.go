package oauth

import "github.com/thoas/go-funk"

// type alias for string slice to create readable functions
type V []string

type Comparator func(a, b string) bool

func (v V) Contains(elements ...string) bool {
	for _, oneElement := range elements {
		if !funk.ContainsString(elements, oneElement) {
			return false
		}
	}
	return true
}

func (v V) ContainsByComparator(elements []string, comparator Comparator) bool {
	for _, oneElement := range elements {
		var containsThisElement bool
		for _, oneValue := range v {
			containsThisElement = comparator(oneValue, oneElement)
			if containsThisElement {
				break
			}
		}
		if !containsThisElement {
			return false
		}
	}
	return true
}

func (v V) ContainsExactly(elements ...string) bool {
	return len(v) == len(elements) && v.Contains(elements...)
}