// See https://aka.ms/new-console-template for more information

using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;

using Spectre.Console;
using Spectre.Console.Cli;

var app = new CommandApp<PwnedPasswordsCommand>();

app.Configure(config => config.PropagateExceptions());

try
{
    return app.Run(args);
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
    return -99;
}

internal sealed class Statistics
{
    public int NumPasswords = 0;
    public int PasswordsProcessed = 0;
    public int PwnedPasswords = 0;
    public int CloudflareRequests = 0;
    public int CloudflareHits = 0;
    public int CloudflareMisses = 0;
    public long CloudflareRequestTimeTotal = 0;
    public long ElapsedMilliseconds = 0;
    public double PwnedPasswordsPercentage => PwnedPasswords / (double)NumPasswords * 100;
    public double CloudflareHitPercentage => CloudflareHits / (double)CloudflareHits * 100;
    public double CloudflareMissPercentage => CloudflareHits / (double)CloudflareHits * 100;
    public double PasswordsPerSec => NumPasswords / ((double)ElapsedMilliseconds / 1000);
}

internal sealed class PwnedPasswordsCommand : Command<PwnedPasswordsCommand.Settings>
{
    internal Channel<string>? _passwords;
    internal Channel<string>? _results;
    internal HttpClient _httpClient = InitializeHttpClient();
    internal Statistics _statistics = new();
    internal string _cacheDir = Path.Combine(Environment.CurrentDirectory, "cache");
    internal static Encoding s_encoding = Encoding.UTF8;
    
    public sealed class Settings : CommandSettings
    {
        [Description("Newline-delimited password list to check against HaveIBeenPwned.")]
        [CommandArgument(0, "[inputFile]")]
        public string InputFile { get; init; } = "";

        [Description("Name of resulting CSV file. Defaults to results.txt.")]
        [CommandArgument(1, "[outputFile]")]
        public string OutputFile { get; init; } = "results.txt";

        [Description("The number of parallel requests to make to HaveIBeenPwned to process the password list. If omitted or 0, defaults to the number of processors on the machine.")]
        [CommandOption("-p||--parallelism")]
        [DefaultValue(0)]
        public int Parallelism { get; set; } = 0;

        [Description("When set, does not cache or use cached HaveIBeenPwned results in the ./cache folder. Defaults to false.")]
        [CommandOption("-c|--skip-cache")]
        [DefaultValue(false)]
        public bool SkipCache { get; set; }

        [Description("When set, clears the ./cache folder before starting processing. Defaults to false.")]
        [CommandOption("-r|--clear-cache")]
        [DefaultValue(false)]
        public bool ClearCache { get; set; }

        public override ValidationResult Validate() => string.IsNullOrEmpty(InputFile) ? ValidationResult.Error("[inputFile] argument is required!") : ValidationResult.Success();
    }

    public override int Execute([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        if(settings.Parallelism == 0)
        {
            settings.Parallelism = Environment.ProcessorCount;
        }

        _passwords = Channel.CreateBounded<string>(new BoundedChannelOptions(settings.Parallelism) { SingleReader = false, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        _results = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });

        InitializeCache(settings);

        Task processingTask = AnsiConsole.Progress()
            .AutoRefresh(false) // Turn off auto refresh
            .AutoClear(false)   // Do not remove the task list when done
            .HideCompleted(false)   // Hide tasks as they are completed
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),    // Task description
                new ProgressBarColumn(),        // Progress bar
                new PercentageColumn(),         // Percentage
                new RemainingTimeColumn(),      // Remaining time
                new SpinnerColumn(),            // Spinner
            })
            .StartAsync(async ctx =>
            {
                var timer = Stopwatch.StartNew();
                _statistics.NumPasswords = CountPasswords(settings.InputFile);

                ProgressTask progressTask = ctx.AddTask("[green]Passwords processed[/]", true, _statistics.NumPasswords);

                Task readTask = ReadPasswords(settings.InputFile);
                Task writeTask = WriteResults(settings.OutputFile);

                var processTask = new List<Task>(settings.Parallelism);
                for (int i = 0; i < settings.Parallelism; i++)
                {
                    processTask.Add(ProcessPassword(settings));
                }

                do
                {
                    progressTask.Value = _statistics.PasswordsProcessed;
                    ctx.Refresh();
                    await Task.Delay(1000).ConfigureAwait(false);
                }
                while (!_passwords.Reader.Completion.IsCompleted);

                var aggregatedProcessTask = Task.WhenAll(processTask);
                await aggregatedProcessTask.ConfigureAwait(false);
                _statistics.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                if (aggregatedProcessTask.Exception != null)
                {
                    Exception baseException = aggregatedProcessTask.Exception.GetBaseException();
                    _results.Writer.TryComplete(baseException);
                    throw baseException;
                }
                else
                {
                    _results.Writer.TryComplete();
                    progressTask.Value = _statistics.PasswordsProcessed;
                    ctx.Refresh();
                }

                await readTask.ConfigureAwait(false);
                await writeTask.ConfigureAwait(false);
                progressTask.StopTask();
            });

        processingTask.Wait();
        AnsiConsole.MarkupLine($"Finished processing {_statistics.NumPasswords:N0} passwords in {_statistics.ElapsedMilliseconds:N0}ms ({_statistics.PasswordsPerSec:N2} passwords per second).");
        AnsiConsole.MarkupLine($"We made {_statistics.CloudflareRequests:N0} Cloudflare requests (avg response time: {(double)_statistics.CloudflareRequestTimeTotal / _statistics.CloudflareRequests:N2}ms). Of those, Cloudflare had already cached {_statistics.CloudflareHits:N0} requests, and made {_statistics.CloudflareMisses:N0} requests to the HaveIBeenPwned origin server.");

        return 0;
    }

    private void InitializeCache(Settings settings)
    {
        if (!Directory.Exists(_cacheDir))
        {
            Directory.CreateDirectory(_cacheDir);
        }
        else if (settings.ClearCache)
        {
            AnsiConsole.Status()
                .Start("Clearing cache...", ctx =>
                {
                    Directory.Delete(_cacheDir, true);
                    Directory.CreateDirectory(_cacheDir);
                });
        }
    }

    private static HttpClient InitializeHttpClient()
    {
        var handler = new HttpClientHandler();

        if (handler.SupportsAutomaticDecompression)
        {
            handler.AutomaticDecompression = DecompressionMethods.All;
        }

        HttpClient client = new(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/range/"), DefaultRequestVersion = new Version(3, 0) };
        string? process = Environment.ProcessPath;
        if (process != null)
        {
            client.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("hibp-speedtest-csharp", FileVersionInfo.GetVersionInfo(process).ProductVersion));
        }

        return client;
    }

    private async Task WriteResults(string outputFile)
    {
        if (_results != null)
        {
            if (File.Exists(outputFile))
            {
                File.Delete(outputFile);
            }

            using FileStream output = File.OpenWrite(outputFile);
            using var stringWriter = new StreamWriter(output);
            await foreach (string? line in _results.Reader.ReadAllAsync())
            {
                await stringWriter.WriteLineAsync(line).ConfigureAwait(false);
            }

            await output.FlushAsync().ConfigureAwait(false);
        }
    }

    private static int CountPasswords(string inputFile)
    {
        int numLines = 0;

        if (!File.Exists(inputFile))
        {
            AnsiConsole.MarkupLine($"[red]File not found[/]: {inputFile}");
            return numLines;
        }

        using (FileStream file = File.OpenRead(inputFile))
        {
            using StreamReader fileReader = new(file);
            string? line = fileReader.ReadLine();
            while (line != null)
            {
                if (!string.IsNullOrEmpty(line))
                {
                    numLines++;
                }

                line = fileReader.ReadLine();
            }
        }

        return numLines;
    }

    private async Task ProcessPassword(Settings settings)
    {
        if (_passwords != null && _results != null)
        {
            await foreach (string? password in _passwords.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                string passwordHash = GetPasswordHash(password);
                string prefix = passwordHash[..5];
                string suffix = passwordHash[5..];
                (bool Exists, int Prevalence) = FindPasswordMatch(await GetPwnedPasswordsRange(prefix, settings.SkipCache).ConfigureAwait(false), suffix);
                Interlocked.Increment(ref _statistics.PasswordsProcessed);
                if (Exists)
                {
                    _results.Writer.TryWrite($"{password},{Prevalence}");
                    Interlocked.Increment(ref _statistics.PwnedPasswords);
                }
                else
                {
                    AnsiConsole.MarkupLine($"[yellow]Password \"{password}\" not found in HaveIBeenPwned.[/]");
                }
            }
        }
    }

    private async Task<string> GetPwnedPasswordsRange(string prefix, bool skipCache)
    {
        if (skipCache)
        {
            return await GetPwnedPasswordsRangeFromWeb(prefix).ConfigureAwait(false);
        }

        string prefixFile = Path.Combine(_cacheDir, $"{prefix}.txt");

        if (File.Exists(prefixFile))
        {
            using FileStream file = File.Open(prefixFile, FileMode.Open, FileAccess.Read, FileShare.Read);
            StreamReader reader = new(file);
            return await reader.ReadToEndAsync().ConfigureAwait(false);
        }

        string content = await GetPwnedPasswordsRangeFromWeb(prefix).ConfigureAwait(false);
        lock (string.Intern(prefix))
        {
            File.WriteAllText(prefixFile, content);
        }

        return content;
    }

    private async Task<string> GetPwnedPasswordsRangeFromWeb(string prefix)
    {
        var cloudflareTimer = Stopwatch.StartNew();
        using var request = new HttpRequestMessage(HttpMethod.Get, prefix);
        using HttpResponseMessage response = await _httpClient.SendAsync(request).ConfigureAwait(false);
        string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        Interlocked.Add(ref _statistics.CloudflareRequestTimeTotal, cloudflareTimer.ElapsedMilliseconds);
        Interlocked.Increment(ref _statistics.CloudflareRequests);
        if (response.Headers.TryGetValues("CF-Cache-Status", out IEnumerable<string>? values) && values != null)
        {
            switch (values.FirstOrDefault())
            {
                case "HIT":
                    Interlocked.Increment(ref _statistics.CloudflareHits);
                    break;
                default:
                    Interlocked.Increment(ref _statistics.CloudflareMisses);
                    break;
            };
        }

        return content;
    }

    private static (bool Exists, int Prevalence) FindPasswordMatch(string pwnedPasswords, string suffix)
    {
        using StringReader reader = new(pwnedPasswords);
        string? pwnedPassword = reader.ReadLine();
        while (pwnedPassword != null)
        {
            if (pwnedPassword.StartsWith(suffix, StringComparison.OrdinalIgnoreCase) && int.TryParse(pwnedPassword[(suffix.Length + 1)..], out int prevalence))
            {
                return (true, prevalence);
            }

            pwnedPassword = reader.ReadLine();
        }

        return (false, 0);
    }

    private static string GetPasswordHash(string password)
    {
        int numBytesRequired = s_encoding.GetByteCount(password);
        byte[] array = ArrayPool<byte>.Shared.Rent(numBytesRequired);
        Span<byte> stringBytes = array.AsSpan(0, numBytesRequired);
        Span<byte> hash = stackalloc byte[20];
        s_encoding.GetBytes(password, stringBytes);
        SHA1.TryHashData(stringBytes, hash, out _);
        ArrayPool<byte>.Shared.Return(array);
        return Convert.ToHexString(hash);
    }

    private async Task ReadPasswords(string inputFile)
    {
        if (_passwords != null)
        {
            FileStream file = File.OpenRead(inputFile);
            using StreamReader reader = new(file);
            string? line = await reader.ReadLineAsync().ConfigureAwait(false);
            int linenum = 0;
            while (line != null)
            {
                linenum++;
                if (!string.IsNullOrEmpty(line))
                {
                    if (!_passwords.Writer.TryWrite(line))
                    {
                        await _passwords.Writer.WriteAsync(line).ConfigureAwait(false);
                    }
                }
                else
                {
                    AnsiConsole.MarkupLine($"[yellow]Invalid password \"{line}\" at line {linenum}[/].");
                }

                line = await reader.ReadLineAsync().ConfigureAwait(false);
            }

            _passwords.Writer.Complete();
        }
    }
}
