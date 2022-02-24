This folder contains the .NET 6.0 (C#) version of the PwnedPasswords Speed Challenge application.

# Building the application
1. Make sure you have the latest .NET 6.0 SDK installed. You can fetch the SDK here: https://dotnet.microsoft.com/en-us/download
2. Download the code, make sure you are in the `csharp` folder and run `dotnet build -c Release` to build a release version of the application. By default this creates an executable in the `HaveIBeenPwned.PwnedPasswordsSpeedChallenge\bin\Release\net6.0` folder. optionally you can provide the `-o .\output` if you want to put the resulting .exe in the `.\output` folder for example.
3. Go the the output folder and run `hibp-speedchallenge --help` to get a list of commands the application supports.

## Example running `--help`:
```
.\hibp-passwordcheck.exe --help

USAGE:
    hibp-passwordcheck.dll [inputFile] [outputFile] [OPTIONS]

ARGUMENTS:
    [inputFile]     Newline-delimited password list to check against HaveIBeenPwned
    [outputFile]    Name of resulting CSV file. Defaults to results.txt

OPTIONS:
    -h, --help           Prints help information
    -p, --parallelism    The number of parallel requests to make to HaveIBeenPwned to process the password list. If omitted or 0, defaults to the number of processors on the machine
    -c, --skip-cache     When set, does not cache or use cached HaveIBeenPwned results in the ./cache folder. Defaults to false
    -r, --clear-cache    When set, clears the ./cache folder before starting processing. Defaults to false
```

## Example running against a file using 64 threads and an empty cache:
```
.\hibp-passwordcheck "C:\Users\stefanj\Downloads\PwnedPasswordsTop100k.txt" -p 64

Invalid password "" at line 4462.
Invalid password "" at line 5599.
Password "Nodefinido" not found in HaveIBeenPwned.
Password "friendofemily" not found in HaveIBeenPwned.
Invalid password "" at line 12662.
Password "friendofGerly" not found in HaveIBeenPwned.
Invalid password "" at line 15672.
Invalid password "" at line 16251.
Invalid password "" at line 17048.
Invalid password "" at line 22106.
Invalid password "" at line 24287.
Password "123456prof_root3.sql.txt:," not found in HaveIBeenPwned.
Password "123456prof_root2.sql.txt:," not found in HaveIBeenPwned.
Password "++++++@mail.ru" not found in HaveIBeenPwned.
Password "contrase+a" not found in HaveIBeenPwned.
Invalid password "" at line 28435.
Invalid password "" at line 28950.
Invalid password "" at line 30392.
Invalid password "" at line 30780.
Invalid password "" at line 31432.
Password "friendofArriane" not found in HaveIBeenPwned.
Invalid password "" at line 35544.
Invalid password "" at line 36350.
Invalid password "" at line 36888.
Invalid password "" at line 38046.
Invalid password "" at line 39114.
Invalid password "" at line 40366.
Invalid password "" at line 45623.
Invalid password "" at line 46368.
Invalid password "" at line 47899.
Invalid password "" at line 48352.
Invalid password "" at line 48573.
Password "friendofThenext18peoplew" not found in HaveIBeenPwned.
Invalid password "" at line 51277.
Invalid password "" at line 54601.
Invalid password "" at line 56499.
Invalid password "" at line 56578.
Invalid password "" at line 58689.
Invalid password "" at line 62406.
Invalid password "" at line 64991.
Invalid password "" at line 65905.
Invalid password "" at line 66415.
Invalid password "" at line 66785.
Invalid password "" at line 68358.
Password "111111prof_root3.sql.txt:," not found in HaveIBeenPwned.
Invalid password "" at line 70884.
Password "friendofEarning$1" not found in HaveIBeenPwned.
Invalid password "" at line 71755.
Password "111111prof_root2.sql.txt:," not found in HaveIBeenPwned.
Invalid password "" at line 73203.
Invalid password "" at line 73204.
Invalid password "" at line 74232.
Invalid password "" at line 77613.
Invalid password "" at line 80192.
Invalid password "" at line 80579.
Invalid password "" at line 80953.
Invalid password "" at line 81460.
Invalid password "" at line 82859.
Invalid password "" at line 84124.
Password "friendofYOUCANMAKE$200-" not found in HaveIBeenPwned.
Password "friendofEveryEmailyouproc" not found in HaveIBeenPwned.
Invalid password "" at line 89671.
Invalid password "" at line 89875.
Invalid password "" at line 92981.
Invalid password "" at line 94693.
Invalid password "" at line 95716.

Passwords processed ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 00:00:00

Finished processing 99.948 passwords in 52.751ms (1.894,71 passwords per second).
We made 99.948 Cloudflare requests (avg response time: 28,37ms). Of those, Cloudflare had already cached 99.948 requests, and made 0 requests to the HaveIBeenPwned origin server.
```