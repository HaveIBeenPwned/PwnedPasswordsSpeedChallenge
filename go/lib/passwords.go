package lib

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

type Password struct {
	Sha        string
	Password   string
	Prevalence int
}

type PasswordPrevalence struct {
	Password   string
	Prevalence int
}

type PasswordList map[string]PasswordPrevalence

// Method to check if a password has already been loaded into the PasswordList.
func (p *Password) IsLoaded(env *Environment) bool {
	env.AllPasswords.Mu.Lock()
	_, passwordPresent := env.AllPasswords.PasswordList[p.Sha]
	env.AllPasswords.Mu.Unlock()

	return passwordPresent
}

// Method to load a password from either cache or API.
func (p *Password) Load(env *Environment) {
	shaPrefix := p.Sha[0:5]
	shaSuffix := p.Sha[5:]

	var data []ApiResponse
	cacheExists := CacheExists(shaPrefix)

	flags := &env.Flags

	if cacheExists && !*flags.SkipCache {
		data = LoadFromCache(shaPrefix)
	} else {
		apiData, err := QueryApi(env, p.Sha)
		if err != nil {
			fmt.Printf("Failed to query API for password: %s \nReason: %s\n", p.Password, err)
			return
		}
		data, err = StructureData(env, apiData)
		if err != nil {
			fmt.Printf("Failed to structure API data for password: %s \nReason: %s\n", p.Password, err)
			return
		}
		AddToCache(shaPrefix, data)
	}

	for _, pwnedPassword := range data {
		if pwnedPassword.Suffix == shaSuffix {
			env.AllPasswords.Mu.Lock()
			defer env.AllPasswords.Mu.Unlock()

			env.AllPasswords.PasswordList[p.Sha] = PasswordPrevalence{
				Password:   p.Password,
				Prevalence: pwnedPassword.Count,
			}
		}
	}
}

// Load passwords into channel for processing.
func PasswordLoader(env *Environment) {
	readFile, err := os.Open("input.txt")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		env.AllPasswords.LoaderWg.Add(1)
		line := fileScanner.Text()
		go func(line string) {
			sha := calcSha(line)
			password := Password{
				Sha:        sha,
				Password:   line,
				Prevalence: 0,
			}
			env.PasswordCh <- &password
		}(line)
	}
}

// Processes passwords loaded into the channel by the PasswordLoader.
func PasswordProcessor(env *Environment) {
	for password := range env.PasswordCh {
		if !password.IsLoaded(env) {
			password.Load(env)
		}
		atomic.AddUint64(&env.ProcessedCount, 1)
		env.AllPasswords.LoaderWg.Done()
	}
}

// Returns the capitalised SHA1 value of a string
func calcSha(password string) string {
	text := password
	data := []byte(text)
	shaBytes := sha1.Sum(data)
	shaString := fmt.Sprintf("%x", shaBytes)
	resp := strings.ToUpper(shaString)
	return resp
}
