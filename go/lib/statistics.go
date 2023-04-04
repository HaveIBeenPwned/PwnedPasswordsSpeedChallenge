package lib

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Calculate the latency of API responses.
func GetApiLatency(env *Environment) string {
	env.ResponseStats.Mu.Lock()
	defer env.ResponseStats.Mu.Unlock()

	var total int64 = 0
	for _, respTime := range env.ResponseStats.ResponseTimes {
		total += respTime
	}
	if total == 0 {
		return "Not Recorded."
	}

	responseCount := int64(len(env.ResponseStats.ResponseTimes))
	if responseCount == 0 {
		return "Not Recorded."
	}

	avgRespTime := total / responseCount

	return fmt.Sprintf("%dms", avgRespTime)
}

// Calculate the percentage of API calls that were cached by Cloudflare.
func CalcCfCache(apiRequestCount int64, cfCachedCount int64) string {

	if apiRequestCount == 0 {
		return "No Requests Made."
	}
	if cfCachedCount == 0 {
		return "No Calls Cached."
	}

	percent := float64(cfCachedCount) / float64(apiRequestCount) * 100
	response := fmt.Sprintf("%d (%.0f%%)", apiRequestCount, percent)

	return response
}

// Update API statistics.
func UpdateAPIStats(env *Environment, respTime int64, cfCacheStatus string) {
	env.ResponseStats.Mu.Lock()
	defer env.ResponseStats.Mu.Unlock()
	env.ResponseStats.ResponseTimes = append(env.ResponseStats.ResponseTimes, respTime)

	atomic.AddInt64(&env.ApiRequestCount, 1)

	if cfCacheStatus == "HIT" || cfCacheStatus == "STALE" || cfCacheStatus == "REVALIDATED" {
		atomic.AddInt64(&env.CfCachedCount, 1)
	}
}

// Display results from collected runtime statistics.
func PresentResults(env *Environment) {
	runtime := time.Since(env.StartTime).Round(time.Millisecond)
	processCount := atomic.LoadUint64(&env.ProcessedCount)
	apiRequestCount := atomic.LoadInt64(&env.ApiRequestCount)
	cfCachedCount := atomic.LoadInt64(&env.CfCachedCount)
	passwordSeconds := (processCount * 1000) / uint64(runtime.Milliseconds())

	fmt.Printf("Total Time Taken: %s \n", runtime)
	fmt.Printf("Passwords Processed: %d @ %d/sec \n", processCount, passwordSeconds)
	fmt.Printf("API Calls: %d \n", apiRequestCount)
	fmt.Printf("Average API Response: %s \n", GetApiLatency(env))
	fmt.Printf("Cloudflare Cached Calls: %s \n", CalcCfCache(apiRequestCount, cfCachedCount))
}
