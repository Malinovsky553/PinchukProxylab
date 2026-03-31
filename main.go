package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

var trustedProxies = []string{"10.10.10.10"}

func main() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/check", checkHandler)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r.RemoteAddr)

	hasForwardedHeaders := r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Forwarded-Proto") != ""

	if hasForwardedHeaders && !isTrustedProxy(ip) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "untrusted proxy",
			"ip":     ip,
		})
		return
	}

	timestamp := r.Header.Get("X-Timestamp")
	if timestamp == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "timestamp is missing",
			"ip":     ip,
		})
		return
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "bad timestamp format",
			"ip":     ip,
		})
		return
	}

	now := time.Now().Unix()
	if abs(now-ts) > 60 {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "timestamp is too old or invalid",
			"ip":     ip,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "allowed",
		"message": "request passed checks",
		"ip":      ip,
	})
}

func getClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func isTrustedProxy(ip string) bool {
	for _, proxyIP := range trustedProxies {
		if ip == proxyIP {
			return true
		}
	}
	return false
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, data map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
