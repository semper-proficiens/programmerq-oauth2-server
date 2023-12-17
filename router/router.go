package router

import "net/http"

type Router interface {
	HandleFunc(pattern string, handler http.HandlerFunc)
}

type DefaultRouter struct{}

func (dr *DefaultRouter) HandleFunc(pattern string, handler http.HandlerFunc) {
	http.HandleFunc(pattern, handler)
}
