package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	initializer "github.com/akshaybt001/DatingApp_Api_Gateway/Initializer"
	"github.com/go-chi/chi"
	"github.com/rs/cors"
)

func main() {
	r := chi.NewRouter()
	r.Use(cors.Default().Handler)

	// Serve static files from the 'template' directory (assuming it's in the same directory)
	FileServer(r, "/template", http.Dir("../template"))

	initializer.Connect(r)

	// Define a template named "index.html" (replace with your actual template name)
	tmpl := template.Must(template.ParseFiles("../template/index.html"))
	prf := template.Must(template.ParseFiles("../template/profile.html"))

	// Handler for the root path ("/") using a template
	rootHandler := func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			Title string // Add any data you want to pass to the template
		}{
			Title: "My Website",
		}
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, fmt.Sprintf("Error rendering template: %v", err), http.StatusInternalServerError)
		}
	}
	profileHandler := func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			Title string
		}{
			Title: "profile",
		}
		if err := prf.Execute(w, data); err != nil {
			http.Error(w, fmt.Sprintf("Error rendering template: %v", err), http.StatusInternalServerError)
		}
	}
	// Register the handler for the root path
	r.Get("/", rootHandler)
	r.Get("/profile", profileHandler)

	fmt.Println("API gateway listening on port 8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

// FileServer conveniently sets up a http.FileServer handler to serve
// static files from a http.FileSystem.
func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit URL parameters.")
	}

	fs := http.StripPrefix(path, http.FileServer(root))

	r.Get(path+"/*", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}
