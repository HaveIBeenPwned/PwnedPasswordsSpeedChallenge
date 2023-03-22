package lib

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ApiResponse struct {
	Suffix string
	Count  int
}

// Structure the API response for caching.
func StructureData(env *Environment, shaList []string) ([]ApiResponse, error) {
	response := []ApiResponse{}

	for _, item := range shaList {
		shaProps := strings.Split(item, ":")
		shaSuffix := shaProps[0]
		rawCount := shaProps[1]

		shaCount, err := strconv.Atoi(strings.TrimSpace(rawCount))
		if err != nil {
			return response, errors.New("can't parse sha count")
		}

		entry := ApiResponse{
			Count:  shaCount,
			Suffix: shaSuffix,
		}

		response = append(response, entry)

	}
	return response, nil
}

// Query the Pwned Passwords API and return the content.
func QueryApi(env *Environment, sha string) ([]string, error) {
	shaPrefix := sha[0:5]
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", shaPrefix)

	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("User-Agent", "hibp-speedtest-go")

	start := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		return []string{}, err
	}
	defer resp.Body.Close()

	respTime := time.Since(start).Milliseconds()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}, err
	}
	bodyString := string(body)

	apiCacheStatus := resp.Header.Get("CF-Cache-Status")
	UpdateAPIStats(env, respTime, apiCacheStatus)

	return strings.Split(bodyString, "\n"), nil
}
