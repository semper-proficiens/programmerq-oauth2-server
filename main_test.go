package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"programmerq-oauth2-server/handlers"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenEndpoint(t *testing.T) {
	data := url.Values{
		"client_id":     {"test_client"},
		"client_secret": {"test_secret"},
		"grant_type":    {"client_credentials"},
		"scope":         {"read"},
	}
	req, err := http.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlers.TokenHandler())
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestProtectedEndpoint(t *testing.T) {
	req, err := http.NewRequest("GET", "/protected", nil)
	assert.NoError(t, err)

	// Replace 'valid_token' with a valid token
	req.Header.Set("Authorization", "Bearer NZAWMMFIZGUTNMUXMC0ZY2YYLTG2ZDATZJDLNDZLMWYWYJLK")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(protectedHandler)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}
