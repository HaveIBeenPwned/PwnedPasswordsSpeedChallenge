# The PwnedPasswords Speed Challenge
This repo contains source code for applications written in different languages to measure how quickly the PwnedPasswords API
can be checked to see if a list of passwords have been breached.

# What should the applications do?
The application should go through each password in the input file, create a SHA1 hash for each password, and use that to query the PwnedPasswords API to see if it finds a match.
If a match is found, the application should output the password and it's prevalence into a CSV file.

The application should preferably use some sort of cache (local storage or memory) for each API request since there is only 1048576 possible hash ranges so for a large file, there
are definitely going to be duplicate requests to the same API endpoint at some point.

The application should also print out the following statistics:
1. How many passwords were checked
2. Total time taken to check all those passwords.
3. How many passwords were checked per second.
4. How many requests were made to the PwnedPasswords API
5. Average PwnedPasswords response time.

Optionally the application could have arguments to skip caching, clearing the cache (if it's local storage) and setting the number of threads to run in parallel.
The applications can also check the `CF-Cache-Status` response header to see if the requests were already cached in Cloudflare or if it had to make requests to
the HIBP origin.

# Input file
The input file should contains a newline delimited list of passwords.
Example:
```
123456
CorrectHorseBatteryStaple
hunter2
```

# Output file
The output file should be a CSV file containing the list of found passwords and their prevalence according to HaveIBeenPwned (numbers correct as of Feb 24th 2022).
Example:
```
123456,37359195
CorrectHorseBatteryStaple,1
hunter2,23496
```
