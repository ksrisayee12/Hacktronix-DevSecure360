package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	http.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id") // Source
		db, _ := sql.Open("mysql", "user:pass@tcp(127.0.0.1:3306)/test")
		query := "SELECT * FROM users WHERE id = " + id
		db.Query(query) // Sink
	})

	http.HandleFunc("/cmdi", func(w http.ResponseWriter, r *http.Request) {
		cmdStr := r.URL.Query().Get("cmd") // Source
		exec.Command(cmdStr).Run()         // Sink
	})

	http.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name") // Source
		fmt.Fprintf(w, "Hello, "+name)    // Sink
	})

	http.HandleFunc("/path", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file") // Source
		os.Open(file)                     // Sink
	})

	http.ListenAndServe(":8080", nil)
}
