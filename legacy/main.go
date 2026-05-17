package main

import (
  "encoding/json"
  "log"
  "net/http"
)

func main() {
  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]string{
      "status":  "ok",
      "service": "legacy-app",
      "message": "legacy application response",
    })
  })

  http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]string{
      "status":  "ok",
      "service": "legacy-app",
      "payload": "some protected legacy data",
    })
  })

  log.Println("legacy app started on :9000")
  log.Fatal(http.ListenAndServe("0.0.0.0:9000", nil))
}