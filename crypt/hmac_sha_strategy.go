package crypt

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

type HmacShaStrategy interface {
	// Generate a new key with signature.
	Generate(entropy uint) (key string, sig string, err error)
	// Verify a key against its signature.
	Verify(key, sig string) error
}

// Create a new HMAC-SHA strategy using SHA-256 algorithm.
func NewHmacSha256Strategy(signingKey []byte) (HmacShaStrategy, error) {
	return newHmacSha(signingKey, 32, sha256.New)
}

// Create a new HMAC-SHA strategy using SHA-384 algorithm.
func NewHmacSha384Strategy(signingKey []byte) (HmacShaStrategy, error) {
	return newHmacSha(signingKey, 48, sha512.New384)
}

// Create a new HMAC-SHA strategy using SHA-512 algorithm.
func NewHmacSha512Strategy(signingKey []byte) (HmacShaStrategy, error) {
	return newHmacSha(signingKey, 64, sha512.New)
}

func newHmacSha(signingKey []byte, sigKeyLen int, hashFunc	func() hash.Hash) (*defaultHmacShaStrategy, error) {
	if len(signingKey) != sigKeyLen {
		return nil, fmt.Errorf("signing key length must be exactly %d bits", sigKeyLen * 8)
	}

	// copy for safety
	copiedSigningKey := make([]byte, len(signingKey))
	copy(copiedSigningKey, signingKey)

	return &defaultHmacShaStrategy{
		signingKey:copiedSigningKey,
		hashFunc:hashFunc,
	}, nil
}