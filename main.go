package main

import (
	"github.com/go-oauth2/oauth2/v4/models"
	"log"
	"net/http"
	"programmerq-oauth2-server/authenticator/oidc/auth0"
	"programmerq-oauth2-server/handlers"
	"programmerq-oauth2-server/router"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

func main() {
	// initialize router
	var r router.Router = &router.DefaultRouter{}

	auth0, err := auth0.New()
	if err != nil {
		log.Fatalf("Failed to initialize the authenticator: %v", err)
	}

	manager := manage.NewDefaultManager()
	// token memory store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// client memory store
	clientStore := store.NewClientStore()
	err = clientStore.Set("test_client", &models.Client{
		ID:     "test_client",
		Secret: "test_secret",
		Domain: "http://localhost",
	})
	if err != nil {
		return
	}
	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	r.HandleFunc("/token", handlers.TokenHandler(srv))
	r.HandleFunc("/authorize", handlers.AuthorizeHandler(srv))
	r.HandleFunc("/login", handlers.LoginHandler())
	r.HandleFunc("/consent", handlers.ConsentHandler())
	r.HandleFunc("/protected", handlers.ProtectedHandler(srv))
	r.HandleFunc("/oidc-auth0", handlers.OIDCAuth0Handler(auth0))
	r.HandleFunc("/oidc-auth0/callback", handlers.OIDCAuth0CallbackHandler(auth0))
	r.HandleFunc("/oidc-auth0/logout", handlers.OIDCAuth0LogoutHandler())
	r.HandleFunc("/user", handlers.UserHandler())

	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("static/styles"))))
	log.Fatal(http.ListenAndServe(":9096", nil))
}
