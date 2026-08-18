package main

import "net/http"

func handler(writer http.ResponseWriter, request *http.Request) {
	label := request.FormValue("label")
	writer.Header().Set("X-Request-Label", label)
	writer.Header().Add("X-Request-Alias", label)
}

func main() {}
