package handlers

import (
	"encoding/gob"
	"fmt"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/gorilla/sessions"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"programmerq-oauth2-server/authenticator/oidc/auth0"
	"programmerq-oauth2-server/util"
	"strings"
)

var store *sessions.CookieStore

// ConsentForm is a struct that holds the data you want to pass to the consent form.
type ConsentForm struct {
	Scopes []string
}

// ResponseCapture captures response from handler. TODO remove after tests
type ResponseCapture struct {
	http.ResponseWriter
	location string
}

func (w *ResponseCapture) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *ResponseCapture) WriteHeader(statusCode int) {
	w.location = w.Header().Get("Location")
	w.ResponseWriter.WriteHeader(statusCode)
}

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
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Check for user in session values.
		user, ok := session.Values["user"]
		if !ok || user == "" {
			// Extract the response_type, client_id and scopes from the request.
			responseType := r.URL.Query().Get("response_type")
			clientId := r.URL.Query().Get("client_id")
			scopes := r.URL.Query().Get("scope")

			log.Printf("Scopes from the session /authorize:%s", scopes)
			// Store the response_type, client_id and scopes in the session.
			session.Values["response_type"] = responseType
			session.Values["client_id"] = clientId
			session.Values["scopes"] = scopes
			err = session.Save(r, w)
			if err != nil {
				log.Printf("Error saving session: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// If the user is not authenticated, redirect them to the login endpoint.
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		log.Print("User Authenticated")
		log.Printf("URL: %v", r.URL)

		// If the user is authenticated, handle the authorize request.
		rw := &ResponseCapture{ResponseWriter: w}
		err = srv.HandleAuthorizeRequest(rw, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Parse the location header to get the code
		if rw.location != "" {
			u, err := url.Parse(rw.location)
			if err != nil {
				log.Printf("Error parsing redirect URL: %s", err)
			} else {
				code := u.Query().Get("code")
				if code != "" {
					log.Printf("Authorization code generated: %s", code)
				}
			}
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
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		scopes, err := util.GetSessionValue(session, "scopes", w)
		if err != nil {
			return
		}

		responseType, err := util.GetSessionValue(session, "response_type", w)
		if err != nil {
			return
		}

		clientId, err := util.GetSessionValue(session, "client_id", w)
		if err != nil {
			return
		}

		log.Printf("Scopes from session /consent non-POST:%s", scopes)
		log.Printf("Response Type from session /consent non-POST:%s", responseType)
		log.Printf("Client ID from session /consent non-POST:%s", clientId)

		if r.Method == "GET" {
			// If it's a GET request, render the consent form.
			// Get the scopes from the session.
			tmpl := template.Must(template.ParseFiles("static/consent.html"))
			tmpl.Execute(w, ConsentForm{
				Scopes: strings.Split(scopes, " "),
			})
			return
		}

		if r.Method == "POST" {
			// Process the form submission here:
			// Get the user's choice from the form.
			choice := r.FormValue("consent")

			if choice == "Grant" {
				authorizeUrl := fmt.Sprintf("/authorize?response_type=%s&client_id=%s&redirect_uri=http://localhost:9096&scope=%s", responseType, clientId, scopes)
				// If the user granted consent, redirect back to /authorize.
				http.Redirect(w, r, authorizeUrl, http.StatusSeeOther)
			} else {
				// If the user denied consent, handle this case as needed.
				// You could redirect them to an error page, for example.
			}
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

		//TODO AuthCodeOption, add VerifierOption
		// gets code from Auth0 and exchanges for a token
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
		session.Values["user"] = profile["nickname"]
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
