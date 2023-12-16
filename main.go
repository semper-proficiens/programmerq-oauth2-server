package main

import (
	"github.com/go-oauth2/oauth2/v4/models"
	"log"
	"net/http"
	"programmerq-oauth2-server/handlers"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

func main() {
	manager := manage.NewDefaultManager()
	// token memory store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// client memory store
	clientStore := store.NewClientStore()
	err := clientStore.Set("test_client", &models.Client{
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

	http.HandleFunc("/token", handlers.TokenHandler(srv))
	http.HandleFunc("/authorize", handlers.AuthorizeHandler(srv))
	http.HandleFunc("/login", handlers.LoginHandler())
	http.HandleFunc("/consent", handlers.ConsentHandler())
	http.HandleFunc("/protected", handlers.ProtectedHandler(srv))
	http.HandleFunc("/oidc", handlers.OIDCHandler())

	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("static/styles"))))
	log.Fatal(http.ListenAndServe(":9096", nil))
}
