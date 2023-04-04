package main

import (
	"fmt"
	"os"
	"psc/lib"
	"strconv"
	"strings"
)

func main() {
	env := lib.SetupEnvironment()

	lib.PasswordLoader(env)

	for i := 0; i < *env.Flags.Parallelism; i++ {
		go lib.PasswordProcessor(env)
	}

	env.AllPasswords.LoaderWg.Wait()

	writeOutput(env.AllPasswords.PasswordList)

	lib.PresentResults(env)
}

// Write the output file containing the prevalence of each password.
func writeOutput(passwords lib.PasswordList) {
	var output strings.Builder

	for _, password := range passwords {
		countAsStr := strconv.Itoa(password.Prevalence)
		output.WriteString(fmt.Sprintf("%s,%s\n", password.Password, countAsStr))
	}
	data := []byte(output.String())

	os.WriteFile("output.txt", data, 0644)
}
