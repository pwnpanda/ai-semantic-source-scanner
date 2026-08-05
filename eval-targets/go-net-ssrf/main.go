// Vulnerable Go HTTP handler doing SSRF via http.Get.
//
// Phase 6 eval target: a single net/http handler that reads the ?url=
// query parameter and feeds it directly into http.Get — no allowlist,
// no validation. The Joern Go frontend should detect r.URL.Query as a
// source and http.Get as a CWE-918 sink.

package main

import (
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	_, _ = w.Write(body)
}

func main() {
	http.HandleFunc("/proxy", handler)
	_ = http.ListenAndServe(":8080", nil)
}
