package lib

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

type ResponseStatistics struct {
	Mu            sync.Mutex
	ResponseTimes []int64
}

type Environment struct {
	StartTime       time.Time
	ResponseStats   ResponseStatistics
	ProcessedCount  uint64
	ApiRequestCount int64
	CfCachedCount   int64
	Flags           Flags
	AllPasswords    SafePasswordList
	PasswordCh      chan *Password
}

type Flags struct {
	SkipCache   *bool
	ClearCache  *bool
	Help        *bool
	Parallelism *int
}

type SafePasswordList struct {
	Mu           sync.Mutex
	PasswordList PasswordList
	LoaderWg     sync.WaitGroup
}

// Prepare the system and application before running.
func SetupEnvironment() *Environment {
	env := Environment{
		StartTime: time.Now(),
		Flags:     loadFlags(),
		AllPasswords: SafePasswordList{
			Mu:           sync.Mutex{},
			PasswordList: make(PasswordList),
			LoaderWg:     sync.WaitGroup{},
		},
	}
	env.PasswordCh = make(chan *Password, *env.Flags.Parallelism)

	handleHelp(env.Flags.Help)
	prepLocalCache(env.Flags.ClearCache, env.Flags.SkipCache)

	return &env
}

// Load command-line arguments.
func loadFlags() Flags {
	var flags = Flags{
		ClearCache:  flag.Bool("clear-cache", false, "Clear local cache and make API calls only."),
		SkipCache:   flag.Bool("skip-cache", false, "Skip local cache and make API calls only."),
		Parallelism: flag.Int("parallelism", 500, "Number of goroutines used to process passwords."),
		Help:        flag.Bool("help", false, "Display command-line arguments."),
	}
	flag.Parse()

	return flags
}

// Handle the help flag.
func handleHelp(help *bool) {
	if *help {
		flag.Usage()
		os.Exit(0)
	}
}

// Prepare the local cache directory.
func prepLocalCache(clearCache *bool, skipCache *bool) {
	if *clearCache {
		os.RemoveAll("./cache")
	}
	createCacheDir()
}

// Create the local cache directory if it doesn't exist.
func createCacheDir() {
	err := os.Mkdir("cache", 0755)
	if err != nil {
		if err.Error() == "mkdir cache: file exists" {
			return
		}
		fmt.Println(err)
		return
	}
}
