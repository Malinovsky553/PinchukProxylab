package main

import (
  "net/http"
  "net/http/httptest"
  "net/url"
  "strconv"
  "strings"
  "testing"
  "time"
)

func resetState() {
  results = nil
  trustedProxies = []string{"10.10.10.10"}
  sessions = map[string]Session{}
}

func performLogin(t *testing.T, username, password string) *http.Cookie {
  form := url.Values{}
  form.Set("username", username)
  form.Set("password", password)

  req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  w := httptest.NewRecorder()

  loginHandler(w, req)

  resp := w.Result()

  if resp.StatusCode != http.StatusSeeOther {
    t.Fatalf("expected redirect after login, got %d", resp.StatusCode)
  }

  cookies := resp.Cookies()
  for _, c := range cookies {
    if c.Name == "session_id" {
      return c
    }
  }

  t.Fatal("session_id cookie was not set")
  return nil
}

func TestHealthHandler(t *testing.T) {
  resetState()

  req := httptest.NewRequest(http.MethodGet, "/health", nil)
  w := httptest.NewRecorder()

  healthHandler(w, req)

  resp := w.Result()
  body := w.Body.String()

  if resp.StatusCode != http.StatusOK {
    t.Errorf("expected status 200, got %d", resp.StatusCode)
  }

  if !strings.Contains(body, `"status":"ok"`) {
    t.Errorf("expected body to contain status ok, got %s", body)
  }
}

func TestCheckHandlerValidTimestamp(t *testing.T) {
  resetState()

  req := httptest.NewRequest(http.MethodGet, "/api/check", nil)
  req.RemoteAddr = "127.0.0.1:12345"
  req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

  w := httptest.NewRecorder()
  checkHandler(w, req)

  resp := w.Result()
  body := w.Body.String()

  if resp.StatusCode != http.StatusOK {
    t.Errorf("expected status 200, got %d", resp.StatusCode)
  }

  if !strings.Contains(body, `"status":"allowed"`) {
    t.Errorf("expected allowed response, got %s", body)
  }
}

func TestCheckHandlerMissingTimestamp(t *testing.T) {
  resetState()

  req := httptest.NewRequest(http.MethodGet, "/api/check", nil)
  req.RemoteAddr = "127.0.0.1:12345"

  w := httptest.NewRecorder()
  checkHandler(w, req)

  resp := w.Result()
  body := w.Body.String()

  if resp.StatusCode != http.StatusForbidden {
    t.Errorf("expected status 403, got %d", resp.StatusCode)
  }

  if !strings.Contains(body, "timestamp is missing") {
    t.Errorf("expected missing timestamp error, got %s", body)
  }
}

func TestCheckHandlerBadTimestampFormat(t *testing.T) {
  resetState()

  req := httptest.NewRequest(http.MethodGet, "/api/check", nil)
  req.RemoteAddr = "127.0.0.1:12345"
  req.Header.Set("X-Timestamp", "abc")

  w := httptest.NewRecorder()
  checkHandler(w, req)

  resp := w.Result()
  body := w.Body.String()

  if resp.StatusCode != http.StatusForbidden {
    t.Errorf("expected status 403, got %d", resp.StatusCode)
  }

  if !strings.Contains(body, "bad timestamp format") {
    t.Errorf("expected bad timestamp format error, got %s", body)
  }
}

func TestCheckHandlerOldTimestamp(t *testing.T) {
  resetState()

  req := httptest.NewRequest(http.MethodGet, "/api/check", nil)
  req.RemoteAddr = "127.0.0.1:12345"
  req.Header.Set("X-Timestamp", "1000")

  w := httptest.NewRecorder()
  checkHandler(w, req)

  resp := w.Result()
  body := w.Body.String()

  if resp.StatusCode != http.StatusForbidden {
    t.Errorf("expected status 403, got %d", resp.StatusCode)
  }

  if !strings.Contains(body, "timestamp is too old or invalid") {
    t.Errorf("expected old timestamp error, got %s", body)
  }
}

func TestCheckHandlerUntrustedProxy(t *testing.T) {
  resetState()

  req := httptest.NewRequest(http.MethodGet, "/api/check", nil)
  req.RemoteAddr = "127.0.0.1:12345"
  req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
  req.Header.Set("X-Forwarded-Proto", "https")

  w := httptest.NewRecorder()
  checkHandler(w, req)

  resp := w.Result()
  body := w.Body.String()

  if resp.StatusCode != http.StatusForbidden {
    t.Errorf("expected status 403, got %d", resp.StatusCode)
  }

  if !strings.Contains(body, "untrusted proxy") {
    t.Errorf("expected untrusted proxy error, got %s", body)
  }
}

func TestLoginSuccessAdmin(t *testing.T) {
  resetState()

  form := url.Values{}
  form.Set("username", "admin")
  form.Set("password", "admin123")

  req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  w := httptest.NewRecorder()

  loginHandler(w, req)

  resp := w.Result()

  if resp.StatusCode != http.StatusSeeOther {
    t.Errorf("expected redirect after login, got %d", resp.StatusCode)
  }

  if len(resp.Cookies()) == 0 {
    t.Errorf("expected session cookie to be set")
  }
}

func TestLoginFail(t *testing.T) {
  resetState()

  form := url.Values{}
  form.Set("username", "admin")
  form.Set("password", "wrong")

  req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  w := httptest.NewRecorder()

  loginHandler(w, req)

  resp := w.Result()
  body := w.Body.String()

  if resp.StatusCode != http.StatusOK {
    t.Errorf("expected status 200 for login page with error, got %d", resp.StatusCode)
  }

  if !strings.Contains(body, "Неверный логин или пароль") {
    t.Errorf("expected login error message, got %s", body)
  }
}

func TestDashboardRequiresAuth(t *testing.T) {
  resetState()

  req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
  w := httptest.NewRecorder()

  handler := authMiddleware([]string{"user", "admin"}, dashboardHandler)
  handler(w, req)

  resp := w.Result()

  if resp.StatusCode != http.StatusSeeOther {
    t.Errorf("expected redirect to login, got %d", resp.StatusCode)
  }
}

func TestDashboardAllowedForUser(t *testing.T) {
  resetState()

  cookie := performLogin(t, "user", "user123")

  req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
  req.AddCookie(cookie)

  w := httptest.NewRecorder()
  handler := authMiddleware([]string{"user", "admin"}, dashboardHandler)
  handler(w, req)

  resp := w.Result()

  if resp.StatusCode != http.StatusOK {
    t.Errorf("expected status 200, got %d", resp.StatusCode)
  }
}

func TestAdminDeniedForUser(t *testing.T) {
  resetState()

  cookie := performLogin(t, "user", "user123")

  req := httptest.NewRequest(http.MethodGet, "/admin", nil)
  req.AddCookie(cookie)

  w := httptest.NewRecorder()
  handler := authMiddleware([]string{"admin"}, adminHandler)
  handler(w, req)

  resp := w.Result()
  body := w.Body.String()

  if resp.StatusCode != http.StatusForbidden {
    t.Errorf("expected status 403, got %d", resp.StatusCode)
  }

  if !strings.Contains(body, "access denied for role") {
    t.Errorf("expected access denied message, got %s", body)
  }
}

func TestAdminAllowedForAdmin(t *testing.T) {
  resetState()

  cookie := performLogin(t, "admin", "admin123")

  req := httptest.NewRequest(http.MethodGet, "/admin", nil)
  req.AddCookie(cookie)

  w := httptest.NewRecorder()
  handler := authMiddleware([]string{"admin"}, adminHandler)
  handler(w, req)

  resp := w.Result()

  if resp.StatusCode != http.StatusOK {
    t.Errorf("expected status 200, got %d", resp.StatusCode)
  }
}

func TestAddProxyByAdmin(t *testing.T) {
  resetState()

  cookie := performLogin(t, "admin", "admin123")

  form := url.Values{}
  form.Set("ip", "127.0.0.1")

  req := httptest.NewRequest(http.MethodPost, "/admin/add-proxy", strings.NewReader(form.Encode()))
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  req.AddCookie(cookie)

  w := httptest.NewRecorder()
  handler := authMiddleware([]string{"admin"}, addProxyHandler)
  handler(w, req)

  resp := w.Result()

  if resp.StatusCode != http.StatusSeeOther {
    t.Errorf("expected redirect after adding proxy, got %d", resp.StatusCode)
  }

  if !isTrustedProxy("127.0.0.1") {
    t.Errorf("expected new proxy to be added")
  }
}

func TestIsTrustedProxy(t *testing.T) {
  resetState()

  if isTrustedProxy("10.10.10.10") != true {
    t.Errorf("expected trusted proxy to return true")
  }

  if isTrustedProxy("127.0.0.1") != false {
    t.Errorf("expected untrusted proxy to return false")
  }
}

func TestAbs(t *testing.T) {
  if abs(-5) != 5 {
    t.Errorf("expected abs(-5) = 5")
  }

  if abs(7) != 7 {
    t.Errorf("expected abs(7) = 7")
  }
}