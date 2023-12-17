package handlers

import (
	"encoding/gob"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/gorilla/sessions"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"programmerq-oauth2-server/authenticator/oidc/auth0"
	"programmerq-oauth2-server/util"
)

var store *sessions.CookieStore

// both store and the gob register need to be called out before other functions, and only once
func init() {
	gob.Register(map[string]interface{}{})
	store = sessions.NewCookieStore([]byte("your-secret-key"))
}

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

// OIDCAuth0Handler for OIDC authentication using Auth0
func OIDCAuth0Handler(auth *auth0.OIDCAuth0Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := util.GenerateRandomState()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// retrieve current session
		session, _ := store.Get(r, "session-name")
		// set session "state" to a random value
		session.Values["state"] = state
		// persist session state in the cookie sent to server
		if err := sessions.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// TODO: AuthCodeURL opts ...AuthCodeOption
		http.Redirect(w, r, auth.AuthCodeURL(state), http.StatusTemporaryRedirect)
	}
}

// OIDCAuth0CallbackHandler the handler for OIDC redirect from Auth0
func OIDCAuth0CallbackHandler(auth *auth0.OIDCAuth0Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")

		// check session id is the same
		if r.URL.Query().Get("state") != session.Values["state"] {
			http.Error(w, "Invalid state parameter.", http.StatusBadRequest)
			return
		}

		// TODO AuthCodeOption
		token, err := auth.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange an authorization code for a token.", http.StatusUnauthorized)
			return
		}

		idToken, err := auth.VerifyIDToken(r.Context(), token)
		if err != nil {
			http.Error(w, "Failed to verify ID Token.", http.StatusInternalServerError)
			return
		}

		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values["access_token"] = token.AccessToken
		session.Values["profile"] = profile
		if err := sessions.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to logged in page.
		http.Redirect(w, r, "/user", http.StatusTemporaryRedirect)
	}
}

func UserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		profile := session.Values["profile"]

		tmpl, err := template.ParseFiles("static/user.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// OIDCAuth0LogoutHandler the handler for OIDC logout from Auth0
func OIDCAuth0LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logoutUrl, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/v2/logout")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}

		returnTo, err := url.Parse(scheme + "://" + r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		parameters := url.Values{}
		parameters.Add("returnTo", returnTo.String())
		parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
		logoutUrl.RawQuery = parameters.Encode()

		http.Redirect(w, r, logoutUrl.String(), http.StatusTemporaryRedirect)
	}
}
