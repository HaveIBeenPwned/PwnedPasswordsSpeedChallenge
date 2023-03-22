package lib

import (
	"encoding/json"
	"fmt"
	"os"
)

// Check if a cache file exists.
func CacheExists(shaPrefix string) bool {
	file := fmt.Sprintf("cache/%s", shaPrefix)
	_, err := os.ReadFile(file)

	return err == nil
}

// Load a cache file.
func LoadFromCache(shaPrefix string) []ApiResponse {
	filename := fmt.Sprintf("cache/%s", shaPrefix)
	var response []ApiResponse

	file, _ := os.ReadFile(filename)
	json.Unmarshal(file, &response)

	return response
}

// Add a cache file for a SHA prefix.
func AddToCache(shaPrefix string, content []ApiResponse) {
	obj, err := json.Marshal(content)
	if err != nil {
		fmt.Println("Failed to marshal request data for creation.")
	}

	filename := fmt.Sprintf("cache/%s", shaPrefix)
	err = os.WriteFile(filename, obj, 0644)
	if err != nil {
		fmt.Printf("Failed to write cache file for prefix: %s\nReason: %s \n", shaPrefix, err)
	}
}
