This folder contains the Python 3 version of the PwnedPasswords Speed Challenge application.

# Running the application
1. Make sure you have Python 3 installed. You can get the latest version here: https://www.python.org/downloads/
2. Download the code, make sure you are in the `python` folder, and run `python PwnedPasswordsSpeedChallenge.py --help` to get a list of commands the application supports.

## Example running `--help`:
```
python PwnedPasswordsSpeedChallenge.py --help
usage: PwnedPasswordsSpeedChallenge.py [-h] [-t THREAD_COUNT] [-i] [-c] [-d] input_file output_file

positional arguments:
  input_file       File with passwords separated by newlines to be checked
  output_file      File to store the results in csv format

options:
  -h, --help       show this help message and exit
  -t THREAD_COUNT  Number of threads to be used, defaults to the CPU count
  -i               Don't use the local cache, defaults to false
  -c               Clear the local cache before starting, defaults to false
  -d               Don't save local cache to disk when completed, defaults to false
```

## Example running against a file using 8 threads and all passwords already cached:
```
python PwnedPasswordsSpeedChallenge.py -t 8 PwnedPasswordsTop100k.txt results.csv

'' not found in HaveIBeenPwned
'++++++@mail.ru' not found in HaveIBeenPwned
'friendofGerly' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'friendofThenext18peoplew' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'contrase+a' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'Nodefinido' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'friendofemily' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'111111prof_root3.sql.txt:,' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'friendofEarning$1' not found in HaveIBeenPwned
'friendofArriane' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'123456prof_root3.sql.txt:,' not found in HaveIBeenPwned
'111111prof_root2.sql.txt:,' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'123456prof_root2.sql.txt:,' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'friendofYOUCANMAKE$200-' not found in HaveIBeenPwned
'' not found in HaveIBeenPwned
'friendofEveryEmailyouproc' not found in HaveIBeenPwned
Finished processing 100000 passwords in 3.864ms (25878.481 passwords per second).
We made 0 Cloudflare requests (avg response time: 0.0ms). Of those, Cloudflare had already cached 0 requests, and made 0 requests to the HaveIBeenPwned origin server.
```
