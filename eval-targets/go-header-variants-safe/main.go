package main

import "net/http"

type Cache struct{}

func (Cache) Set(_ string, _ string) {}
func (Cache) Add(_ string, _ string) {}

func handler(writer http.ResponseWriter, request *http.Request, cache Cache) {
	value := request.FormValue("value")
	cache.Set("request", value)
	cache.Add("request", value)
	writer.Header().Set("X-Request-Label", "fixed")
}

func main() {}
