package crypt

import (
	"crypto/rand"
	"io"
)

// Returns n random bytes.
func RandomBytes(n uint) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return []byte{}, err
	}
	return bytes, nil
}
