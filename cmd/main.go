package main

import (
	"fmt"
	"net/http"

	initializer "github.com/akshaybt001/DatingApp_Api_Gateway/Initializer"
	"github.com/go-chi/chi"
	"github.com/rs/cors"
)

func main() {
	r := chi.NewRouter()
	r.Use(cors.Default().Handler)

	initializer.Connect(r)
	fmt.Println("api gateway listening on port 8080")
	http.ListenAndServe(":8080", r)
}
