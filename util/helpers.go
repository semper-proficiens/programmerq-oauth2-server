package util

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gorilla/sessions"
	"net/http"
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

// GetSessionValue tries to retrieve a given session value with a given key and returns the value or returns an error.
func GetSessionValue(session *sessions.Session, key string, w http.ResponseWriter) (string, error) {
	value, ok := session.Values[key].(string)
	if !ok {
		http.Error(w, fmt.Sprintf("%s not found in session", key), http.StatusInternalServerError)
		return "", fmt.Errorf("%s not found in session", key)
	}
	return value, nil
}
