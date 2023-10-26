package main

import (
	"net/http"

	"totp-sample/handler"
)

func main() {
	h := handler.Handler()
	if err := http.ListenAndServe(":8080", h); err != nil {
		panic(err)
	}
}
