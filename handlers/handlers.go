package handlers

import (
	"github.com/go-oauth2/oauth2/v4/server"
	"html/template"
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

// AuthorizeHandler handles authorization requests
func AuthorizeHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated.
		// In a real application, you would check a session or a secure cookie to see if the user is authenticated.
		// Here, we'll just check if a "user" cookie exists.
		userCookie, err := r.Cookie("user")
		if err != nil || userCookie.Value == "" {
			// If the user is not authenticated, redirect them to the login endpoint.
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// If the user is authenticated, handle the authorize request.
		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// LoginHandler for user login
func LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// On a GET request, render the login form.
		if r.Method == "GET" {
			tmpl := template.Must(template.ParseFiles("static/login.html"))
			tmpl.Execute(w, nil)
			return
		}

		// On a POST request, handle the form submission.
		// Here, you would authenticate the user, generate a JWT, etc.
	}
}

// ConsentHandler for user consent
func ConsentHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// Here, you should check the user's consent.
			// If the user has given consent, you can store this information in a session or a secure cookie.
			// Then, redirect the user back to the /authorize endpoint.
		} else {
			// If it's a GET request, render the consent form.
		}
	}
}

// OIDCHandler for OIDC authentication
func OIDCHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://your-oidc-provider.com/authorize?...", http.StatusSeeOther)
	}
}
