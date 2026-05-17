package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

var trustedProxies = []string{"10.10.10.10", "127.0.0.1"}

var users = map[string]User{
	"admin": {
		Username: "admin",
		Password: "admin123",
		Role:     "admin",
	},
	"user": {
		Username: "user",
		Password: "user123",
		Role:     "user",
	},
}

type User struct {
	Username string
	Password string
	Role     string
}

type Session struct {
	Username string
	Role     string
	Created  time.Time
}

var sessions = map[string]Session{}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	http.HandleFunc("/", authMiddleware([]string{"user", "admin"}, dashboardHandler))
	http.HandleFunc("/dashboard", authMiddleware([]string{"user", "admin"}, dashboardHandler))

	http.HandleFunc("/admin", authMiddleware([]string{"admin"}, adminHandler))
	http.HandleFunc("/admin/add-proxy", authMiddleware([]string{"admin"}, addProxyHandler))

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/check", checkHandler)

	log.Println("security container started on :8080")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}

func authMiddleware(allowedRoles []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := getSessionFromRequest(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		for _, allowedRole := range allowedRoles {
			if session.Role == allowedRole {
				handler(w, r)
				return
			}
		}

		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "access denied for role",
			"role":   session.Role,
		})
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles("security/templates/login.html")
		if err != nil {
			http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		data := map[string]any{
			"Error": "",
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
		return
	}

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"status": "blocked",
			"reason": "only GET and POST methods are allowed",
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, exists := users[username]
	if !exists || user.Password != password {
		tmpl, err := template.ParseFiles("security/templates/login.html")
		if err != nil {
			http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		data := map[string]any{
			"Error": "Неверный логин или пароль",
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
		return
	}

	sessionID := generateSessionID()
	sessions[sessionID] = Session{
		Username: user.Username,
		Role:     user.Role,
		Created:  time.Now(),
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   3600,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		delete(sessions, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func getSessionFromRequest(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return Session{}, false
	}

	session, ok := sessions[cookie.Value]
	if !ok {
		return Session{}, false
	}

	return session, true
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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

	timestamp := r.Header.Get("X-Timestamp")

	if hasForwardedHeaders && !isTrustedProxy(ip) {
		addResult(ip, hasForwardedHeaders, timestamp, "blocked", "untrusted proxy")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "untrusted proxy",
			"ip":     ip,
		})
		return
	}

	if timestamp == "" {
		addResult(ip, hasForwardedHeaders, timestamp, "blocked", "timestamp is missing")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "timestamp is missing",
			"ip":     ip,
		})
		return
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		addResult(ip, hasForwardedHeaders, timestamp, "blocked", "bad timestamp format")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "bad timestamp format",
			"ip":     ip,
		})
		return
	}

	now := time.Now().Unix()
	if abs(now-ts) > 60 {
		addResult(ip, hasForwardedHeaders, timestamp, "blocked", "timestamp is too old or invalid")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "timestamp is too old or invalid",
			"ip":     ip,
		})
		return
	}

	addResult(ip, hasForwardedHeaders, timestamp, "allowed", "-")
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "allowed",
		"message": "request passed checks",
		"ip":      ip,
	})
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("security/templates/index.html")
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := getSessionFromRequest(r)

	data := map[string]any{
		"Results":        getResults(),
		"TrustedProxies": trustedProxies,
		"Role":           session.Role,
		"Username":       session.Username,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("security/templates/admin.html")
		if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := getSessionFromRequest(r)

	data := map[string]any{
		"TrustedProxies": trustedProxies,
		"Username":       session.Username,
		"Role":           session.Role,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

func addProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"status": "blocked",
			"reason": "only POST method is allowed",
		})
		return
	}

	ip := r.FormValue("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"status": "blocked",
			"reason": "ip is missing",
		})
		return
	}

	if !isTrustedProxy(ip) {
		trustedProxies = append(trustedProxies, ip)
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
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
	_ = json.NewEncoder(w).Encode(data)
}
	
//curl http://127.0.0.1:8080/health - серв работает
//curl -i http://127.0.0.1:8080/api/check -H "X-Timestamp: $(date +%s)" - корректный запрос проходит (есть время и нет прокси)
//curl -i http://127.0.0.1:8080/api/check - запрос без времени блокируется
//curl -i http://127.0.0.1:8080/api/check -H "X-Timestamp: $(date +%s)" -H "X-Forwarded-Proto: https" - запрос с недоверенным прокси блокируется
// ПРОВЕРКА ЧЕРЕЗ ШЕЛЛ

// /admin?role=admin админка
// /dashboard?role=admin дашборд админа
// /admin?role=user не даст юзеру увидеть админпанель
// /dashboard?role=user дашборд юзера