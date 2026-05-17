package main

import (
  "fmt"
  "sync"
)

type CheckResult struct {
  Number   int
  IP       string
  Proxy    string
  TimeInfo string
  Status   string
  Reason   string
}

var (
  results   []CheckResult
  resultsMu sync.Mutex
)

func addResult(ip string, hasForwardedHeaders bool, timestamp string, status string, reason string) {
  resultsMu.Lock()
  defer resultsMu.Unlock()

  proxy := "no"
  if hasForwardedHeaders {
    proxy = "yes"
  }

  if timestamp == "" {
    timestamp = "missing"
  }

  result := CheckResult{
    Number:   len(results) + 1,
    IP:       ip,
    Proxy:    proxy,
    TimeInfo: timestamp,
    Status:   status,
    Reason:   reason,
  }

  results = append(results, result)
  printResultsTable()
}

func getResults() []CheckResult {
  resultsMu.Lock()
  defer resultsMu.Unlock()

  copyResults := make([]CheckResult, len(results))
  copy(copyResults, results)

  return copyResults
}

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