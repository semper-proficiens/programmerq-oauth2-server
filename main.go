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
	clientStore.Set("test_client", &models.Client{
		ID:     "test_client",
		Secret: "test_secret",
		Domain: "http://localhost",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	http.HandleFunc("/token", handlers.TokenHandler(srv))
	http.HandleFunc("/protected", handlers.ProtectedHandler(srv))

	log.Fatal(http.ListenAndServe(":9096", nil))
}
