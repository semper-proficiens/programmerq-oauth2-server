package handlers

import (
	"github.com/go-oauth2/oauth2/v4/server"
	"net/http"
)

// TokenHandler handles token requests.
func TokenHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srv.HandleTokenRequest(w, r)
	}
}

// ProtectedHandler handles token requests.
func ProtectedHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Write([]byte("Hello, protected area"))
	}
}
