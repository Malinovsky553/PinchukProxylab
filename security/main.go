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

// Список доверенных прокси
var trustedProxies = []string{"10.10.10.10", "127.0.0.1"}

// Учетные записи пользователей
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

// Структура пользователя
type User struct {
	Username string
	Password string
	Role     string
}

// Структура сессии
type Session struct {
	Username string
	Role     string
	Created  time.Time
}

// Хранилище сессий
var sessions = map[string]Session{}

// Главная функция запуска
func main() {
	// Маршруты авторизации
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	// Маршруты интерфейса
	http.HandleFunc("/", authMiddleware([]string{"user", "admin"}, dashboardHandler))
	http.HandleFunc("/dashboard", authMiddleware([]string{"user", "admin"}, dashboardHandler))

	// Маршруты администратора
	http.HandleFunc("/admin", authMiddleware([]string{"admin"}, adminHandler))
	http.HandleFunc("/admin/add-proxy", authMiddleware([]string{"admin"}, addProxyHandler))

	// Служебные маршруты
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/check", checkHandler)

	log.Println("security container started on :8080")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}

// Проверка роли пользователя
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

// Обработчик входа
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

	// Создаем сессию
	sessionID := generateSessionID()
	sessions[sessionID] = Session{
		Username: user.Username,
		Role:     user.Role,
		Created:  time.Now(),
	}

	// Сохраняем session_id
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

// Обработчик выхода
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

// Получение сессии из cookie
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

// Генерация случайного ID сессии
func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Проверка, что сервис работает
func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// Основная проверка запроса
func checkHandler(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r.RemoteAddr)

	// Смотрим, есть ли признаки прокси
	hasForwardedHeaders := r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Forwarded-Proto") != ""

	// Получаем timestamp
	timestamp := r.Header.Get("X-Timestamp")

	// Если прокси недоверенный, блокируем
	if hasForwardedHeaders && !isTrustedProxy(ip) {
		addResult(ip, hasForwardedHeaders, timestamp, "blocked", "untrusted proxy")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "untrusted proxy",
			"ip":     ip,
		})
		return
	}

	// Если нет timestamp, блокируем
	if timestamp == "" {
		addResult(ip, hasForwardedHeaders, timestamp, "blocked", "timestamp is missing")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"status": "blocked",
			"reason": "timestamp is missing",
			"ip":     ip,
		})
		return
	}

	// Проверяем формат timestamp
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

	// Проверяем, не устарел ли timestamp
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

	// Если все проверки прошли
	addResult(ip, hasForwardedHeaders, timestamp, "allowed", "-")
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "allowed",
		"message": "request passed checks",
		"ip":      ip,
	})
}

// Страница мониторинга
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

// Подсчет аналитики для страницы администратора
func buildAnalytics(results []CheckResult) map[string]any {
	allowedCount := 0
	blockedCount := 0

	reasons := map[string]int{
		"untrusted proxy":                 0,
		"timestamp is missing":            0,
		"bad timestamp format":            0,
		"timestamp is too old or invalid": 0,
	}

	for _, r := range results {
		if r.Status == "allowed" {
			allowedCount++
		}
		if r.Status == "blocked" {
			blockedCount++
			if _, ok := reasons[r.Reason]; ok {
				reasons[r.Reason]++
			}
		}
	}

	return map[string]any{
		"AllowedCount": allowedCount,
		"BlockedCount": blockedCount,
		"Reasons":      reasons,
	}
}

// Страница администратора
func adminHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("security/templates/admin.html")
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := getSessionFromRequest(r)
	results := getResults()
	analytics := buildAnalytics(results)

	data := map[string]any{
		"TrustedProxies": trustedProxies,
		"Username":       session.Username,
		"Role":           session.Role,
		"AllowedCount":   analytics["AllowedCount"],
		"BlockedCount":   analytics["BlockedCount"],
		"Reasons":        analytics["Reasons"],
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

// Добавление нового доверенного прокси
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

// Получение IP клиента
func getClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// Проверка доверенного прокси
func isTrustedProxy(ip string) bool {
	for _, proxyIP := range trustedProxies {
		if ip == proxyIP {
			return true
		}
	}
	return false
}

// Модуль числа
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// Отправка JSON-ответа
func writeJSON(w http.ResponseWriter, status int, data map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}