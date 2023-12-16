package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func TestTokenAndProtectedHandler(t *testing.T) {
	data := url.Values{
		"client_id":     {"test_client"},
		"client_secret": {"test_secret"},
		"grant_type":    {"client_credentials"},
		"scope":         {"read"},
	}

	resp, err := http.PostForm("http://localhost:9096/token", data)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	var respJSON tokenResponse
	err = json.Unmarshal(body, &respJSON)
	require.NoError(t, err)

	// Test the protected endpoint
	req, err := http.NewRequest("GET", "http://localhost:9096/protected", nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", "Bearer "+respJSON.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
