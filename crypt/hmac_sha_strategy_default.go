package crypt

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"hash"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.NoPadding)
	errSignatureMismatch = errors.New("signature mismatch")
)

type defaultHmacShaStrategy struct {
	// Secret key for signing the generated key
	signingKey 		[]byte
	// Function to generate a new hmac-sha hash
	hashFunc		func() hash.Hash
}

func (h *defaultHmacShaStrategy) Generate(entropy uint) (string, string, error) {
	rawKey, err := randomBytes(entropy)
	if err != nil {
		return "", "", err
	}

	rawSig := h.sign(rawKey, h.signingKey)

	return b64.EncodeToString(rawKey), b64.EncodeToString(rawSig), nil
}

func (h *defaultHmacShaStrategy) Verify(key, sig string) error {
	var (
		err	error
	)

	rawKey, err := b64.DecodeString(key)
	if err != nil {
		return err
	}

	rawSig, err := b64.DecodeString(sig)
	if err != nil {
		return err
	}

	expectSig := h.sign(rawKey, h.signingKey)
	if !hmac.Equal(expectSig, rawSig) {
		return errSignatureMismatch
	}

	return nil
}

func (h *defaultHmacShaStrategy) sign(data []byte, key []byte) []byte {
	hs := hmac.New(h.hashFunc, key[:])
	hs.Write(data)
	return hs.Sum(nil)
}