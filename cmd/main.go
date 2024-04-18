package main

import (
	"github.com/rs/cors"
	"github.com/go-chi/chi"
)

func main(){
	r:=chi.NewRouter()
	r.Use(cors.Default().Handler)
	
}