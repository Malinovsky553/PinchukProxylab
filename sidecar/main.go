package main

import (
  "encoding/json"
  "io"
  "log"
  "net/http"
  "net/url"
  "os"
  "strconv"
  "strings"
  "time"
)

func main() {
  legacyURL := getEnv("LEGACY_APP_URL", "http://127.0.0.1:9000")
  securityURL := getEnv("SECURITY_CONTAINER_URL", "http://127.0.0.1:8080/api/check")
  publicBaseURL := getEnv("PUBLIC_BASE_URL", "https://company1.example")
  port := getEnv("PORT", "8090")

  mux := http.NewServeMux()

  mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
    writeJSON(w, http.StatusOK, map[string]string{
      "status":  "ok",
      "service": "sidecar",
    })
  })

  mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    forwardedProto := r.Header.Get("X-Forwarded-Proto")

    if forwardedProto != "https" {
      target := publicBaseURL + r.URL.RequestURI()
      http.Redirect(w, r, target, http.StatusMovedPermanently)
      return
    }

    securityReq, err := http.NewRequest(http.MethodGet, securityURL, nil)
    if err != nil {
      writeJSON(w, http.StatusInternalServerError, map[string]string{
        "status": "blocked",
        "reason": "security request build failed",
      })
      return
    }

    securityReq.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
    securityReq.Header.Set("X-Forwarded-Proto", "https")

    client := &http.Client{Timeout: 5 * time.Second}
    securityResp, err := client.Do(securityReq)
    if err != nil {
      writeJSON(w, http.StatusBadGateway, map[string]string{
        "status": "blocked",
        "reason": "security container unavailable",
      })
      return
    }
    defer securityResp.Body.Close()

    if securityResp.StatusCode != http.StatusOK {
      body, _ := io.ReadAll(securityResp.Body)
      w.Header().Set("Content-Type", "application/json")
      w.WriteHeader(http.StatusForbidden)
      _, _ = w.Write(body)
      return
    }

    targetURL, err := url.Parse(legacyURL)
    if err != nil {
      writeJSON(w, http.StatusInternalServerError, map[string]string{
        "status": "blocked",
        "reason": "legacy url parse failed",
      })
      return
    }

    targetURL.Path = joinURLPath(targetURL.Path, r.URL.Path)
    targetURL.RawQuery = r.URL.RawQuery

    proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
    if err != nil {
      writeJSON(w, http.StatusInternalServerError, map[string]string{
        "status": "blocked",
        "reason": "proxy request build failed",
      })
      return
    }

    copyHeaders(proxyReq.Header, r.Header)
    proxyReq.Header.Set("X-Forwarded-Proto", "https")
    proxyReq.Header.Set("X-Sidecar-Adapter", "enabled")

    proxyResp, err := client.Do(proxyReq)
    if err != nil {
      writeJSON(w, http.StatusBadGateway, map[string]string{
        "status": "blocked",
        "reason": "legacy application unavailable",
      })
      return
    }
    defer proxyResp.Body.Close()

    copyHeaders(w.Header(), proxyResp.Header)
    w.WriteHeader(proxyResp.StatusCode)
    _, _ = io.Copy(w, proxyResp.Body)
  })

  log.Println("sidecar started on :" + port)
  log.Fatal(http.ListenAndServe("0.0.0.0:"+port, mux))
}

func getEnv(name, fallback string) string {
  value := os.Getenv(name)
  if value == "" {
    return fallback
  }
  return value
}

func writeJSON(w http.ResponseWriter, status int, data map[string]string) {
  w.Header().Set("Content-Type", "application/json")
  w.WriteHeader(status)
  _ = json.NewEncoder(w).Encode(data)
}

func copyHeaders(dst, src http.Header) {
  for k, values := range src {
    for _, v := range values {
      dst.Add(k, v)
    }
  }
}

func joinURLPath(basePath, requestPath string) string {
  if basePath == "" || basePath == "/" {
    return requestPath
  }
  if requestPath == "" || requestPath == "/" {
    return basePath
  }
  return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(requestPath, "/")
}