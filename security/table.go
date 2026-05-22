package main

import (
  "fmt"
  "sync"
)

// Структура одной записи о проверке запроса
type CheckResult struct {
  Number   int
  IP       string
  Proxy    string
  TimeInfo string
  Status   string
  Reason   string
}

// Слайс для хранения результатов и mutex для безопасной работы с ними
var (
  results   []CheckResult
  resultsMu sync.Mutex
)

// Добавление новой записи в историю проверок
func addResult(ip string, hasForwardedHeaders bool, timestamp string, status string, reason string) {
  resultsMu.Lock()
  defer resultsMu.Unlock()

  // Если есть прокси-заголовки, пишем yes, иначе no
  proxy := "no"
  if hasForwardedHeaders {
    proxy = "yes"
  }

  // Если timestamp не передан, выводим missing
  if timestamp == "" {
    timestamp = "missing"
  }

  // Формируем объект результата
  result := CheckResult{
    Number:   len(results) + 1,
    IP:       ip,
    Proxy:    proxy,
    TimeInfo: timestamp,
    Status:   status,
    Reason:   reason,
  }

  // Добавляем результат в общий список
  results = append(results, result)

  // После добавления выводим таблицу в консоль
  printResultsTable()
}

// Получение копии списка результатов для веб-интерфейса
func getResults() []CheckResult {
  resultsMu.Lock()
  defer resultsMu.Unlock()

  copyResults := make([]CheckResult, len(results))
  copy(copyResults, results)

  return copyResults
}

// Вывод таблицы результатов в консоль Replit
func printResultsTable() {
  fmt.Println()
  fmt.Println("-------------------------------------------------------------------------------------------")
  fmt.Printf("| %-3s | %-12s | %-7s | %-15s | %-8s | %-30s |\n",
    "No", "IP", "Proxy", "Timestamp", "Status", "Reason")
  fmt.Println("-------------------------------------------------------------------------------------------")

  for _, result := range results {
    fmt.Printf("| %-3d | %-12s | %-7s | %-15s | %-8s | %-30s |\n",
      result.Number,
      result.IP,
      result.Proxy,
      result.TimeInfo,
      result.Status,
      result.Reason)
  }

  fmt.Println("-------------------------------------------------------------------------------------------")
  fmt.Println()
}