package util

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
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

// EnvironmentVarIsNotEmpty helper to check whether an environment variable value key is empty or not.
// It throws an error if empty
func EnvironmentVarIsNotEmpty(envVarKey string) error {
	envVarValue := os.Getenv(envVarKey)
	if envVarValue == "" {
		return errors.New(fmt.Sprintf("environment variable '%s' can't be empty", envVarKey))
	}
	return nil
}
