This folder contains the Go version of the PwnedPasswords Speed Challenge application.

## Pre-Requisites

You must have:

- [Go](https://go.dev) Installed.
- Have an `input.txt` file containing your password list in the `go` directory.

## Running the application

You can run the application without building it by running the following command in the `go` directory.

```shell
go run . --help
```

## Building the application

You can build a native binary of the application by running the below command in the `go` directory:

```go
go build .
```

The binary can be executed by calling it from the command line:

```shell
./psc --help
```

## Command-line arguments

You can access the command line arguments by using the `--help` flag as demonstrated above.

```shell
Usage of ./psc:
  -clear-cache
        Clear local cache and make API calls only.
  -help
        Display command-line arguments.
  -parallelism int
        Number of goroutines used to process passwords. (default 500)
  -skip-cache
        Skip local cache and make API calls only.
```

**Notes:**

- The application accepts both `--` and `-` variations of argument prefix.
- Although goroutines provide concurrency (which is not strictly parallelism) the `parallelism` phrase has been chosen for the flag to maintain consistency with the csharp implementation.

# Potential Improvements

This implementation could be further improved by:

- Hashing all passwords upfront and grouping by SHA prefix to reduce the required API calls and disk IO.
- Reduced mutex usage.
- Better network handling:
  - Error handling (Retries & exponential backoff)
- Tests
