package util

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateRandomState helper to produce a base64 random state
func GenerateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)

	return state, nil
}
