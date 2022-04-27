using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswordsSpeedChallenge;

using Microsoft.Win32.SafeHandles;

using Polly;
using Polly.Extensions.Http;
using Polly.Retry;

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
    internal Statistics _statistics = new();
    internal string _cacheDir = Path.Combine(Environment.CurrentDirectory, "cache");
    internal static Encoding s_encoding = Encoding.UTF8;
    internal HttpClient _httpClient = InitializeHttpClient();
    internal ConcurrentStack<List<HashEntry>> _hashEntries = new();
    internal SemaphoreSlim[] _semaphores = new SemaphoreSlim[256*256];
    internal AsyncRetryPolicy<HttpResponseMessage> _policy = HttpPolicyExtensions.HandleTransientHttpError().RetryAsync(5);
    internal ArrayPool<byte> _pool = ArrayPool<byte>.Create();

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
        if (settings.Parallelism == 0)
        {
            settings.Parallelism = Environment.ProcessorCount;
        }

        _passwords = Channel.CreateBounded<string>(new BoundedChannelOptions(settings.Parallelism * 16) { SingleReader = false, SingleWriter = true });
        _results = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });
        for(int i = 0; i < _semaphores.Length; i++)
        {
            _semaphores[i] = new SemaphoreSlim(1);
        }

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
                _statistics.NumPasswords = Helpers.CountLines(settings.InputFile);

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
                    await Task.Delay(100).ConfigureAwait(false);
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
        AnsiConsole.MarkupLine($"Finished checking {_statistics.NumPasswords:N0} passwords in {_statistics.ElapsedMilliseconds:N0}ms ({_statistics.PasswordsPerSec:N2} passwords per second). We found {_statistics.PwnedPasswords:N0} pwned passwords ({_statistics.PwnedPasswordsPercentage:N2}%).");
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
                    Parallel.ForEach(Directory.EnumerateFiles(_cacheDir, "*", SearchOption.AllDirectories), item => File.Delete(item));
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

        HttpClient client = new(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/range/"), DefaultRequestVersion = HttpVersion.Version20 };
        string? process = Environment.ProcessPath;
        if (process != null)
        {
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("hibp-speedtest-csharp", FileVersionInfo.GetVersionInfo(process).ProductVersion));
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

            byte[] array = _pool.Rent(16384);
            Memory<byte> memory = array.AsMemory(0, 16384);
            using SafeFileHandle handle = File.OpenHandle(outputFile, FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.Asynchronous);
            int offset = 0;
            while (await _results.Reader.WaitToReadAsync().ConfigureAwait(false))
            {
                int totalBytes = 0;
                while (_results.Reader.TryRead(out string? line) && line is not null)
                {
                    int byteCount = s_encoding.GetByteCount(line) + 2;
                    if ((totalBytes + byteCount) > memory.Length)
                    {
                        await RandomAccess.WriteAsync(handle, memory.Slice(0, totalBytes), offset).ConfigureAwait(false);
                        offset += totalBytes;
                        totalBytes = 0;
                    }

                    int index = totalBytes + byteCount;
                    s_encoding.GetBytes(line, memory.Span.Slice(totalBytes, byteCount));
                    memory.Span[index - 2] = (byte)'\r';
                    memory.Span[index - 1] = (byte)'\n';
                    totalBytes += byteCount;
                }

                if (totalBytes > 0)
                {
                    await RandomAccess.WriteAsync(handle, memory.Slice(0, totalBytes), offset).ConfigureAwait(false);
                    offset += totalBytes;
                }
            }

            _pool.Return(array);
        }
    }

    private async Task ProcessPassword(Settings settings)
    {
        if (_passwords != null && _results != null)
        {
            byte[] hashBytes = _pool.Rent(20);
            Memory<byte> hashMemory = hashBytes.AsMemory(0, 20);

            while (await _passwords.Reader.WaitToReadAsync().ConfigureAwait(false))
            {
                while (_passwords.Reader.TryRead(out string? password))
                {
                    password.GetSha1Hash(hashMemory);
                    List<HashEntry> hashEntries = await GetPwnedPasswordsRange(hashMemory, settings.SkipCache).ConfigureAwait(false);
                    (bool Exists, int Prevalence) = FindPasswordMatch(hashEntries, hashMemory[2..].Span);
                    _hashEntries.Push(hashEntries);
                    Interlocked.Increment(ref _statistics.PasswordsProcessed);
                    if (Exists)
                    {
                        _results.Writer.TryWrite($"{password},{Prevalence}");
                        Interlocked.Increment(ref _statistics.PwnedPasswords);
                    }
                    else
                    {
                        AnsiConsole.MarkupLine($"[yellow]Password \"{password.EscapeMarkup()}\" not found in HaveIBeenPwned.[/]");
                    }
                }
            }

            _pool.Return(hashBytes);
        }
    }

    private async Task<List<HashEntry>> GetPwnedPasswordsRange(ReadOnlyMemory<byte> hash, bool skipCache)
    {
        List<HashEntry> entries = GetHashList();

        if (skipCache)
        {
            return await GetPwnedPasswordsRangeFromWeb(hash, entries).ConfigureAwait(false);
        }

        string prefix = Convert.ToHexString(hash.Span[..3])[..5];
        string prefixFile = Path.Combine(_cacheDir, $"{prefix}.txt");
        ushort semaphoreIndex = BinaryPrimitives.ReadUInt16BigEndian(hash.Span);
        SemaphoreSlim semaphore = _semaphores[semaphoreIndex];
        await semaphore.WaitAsync().ConfigureAwait(false); // Let's lock on the first byte of the prefix
        byte[]? tempArray = null;
        try
        {
            using SafeFileHandle? handle = File.OpenHandle(prefixFile, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.SequentialScan | FileOptions.Asynchronous);
            int numEntries = (int)RandomAccess.GetLength(handle) / 22;
            tempArray = _pool.Rent(numEntries * 22);
            Memory<byte> tempMemory = tempArray.AsMemory(0, numEntries * 22);
            await RandomAccess.ReadAsync(handle, tempMemory, 0).ConfigureAwait(false);

            for (int i = 0; i < numEntries; i++)
            {
                int index = i * 22;
                if (HashEntry.TryRead(tempMemory.Span.Slice(index, 22), out HashEntry entry))
                {
                    entries.Add(entry);
                }
            }

        }
        catch (FileNotFoundException)
        {
            await GetPwnedPasswordsRangeFromWeb(hash, entries).ConfigureAwait(false);
            int totalBytes = entries.Count * 22;
            using SafeFileHandle handle = File.OpenHandle(prefixFile, FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.Asynchronous, totalBytes);
            tempArray = _pool.Rent(totalBytes);
            Memory<byte> tempMemory = tempArray.AsMemory(0, totalBytes);
            for (int i = 0; i < entries.Count; i++)
            {
                int index = i * 22;
                entries[i].TryWrite(tempMemory.Span.Slice(index, 22));
            }

            await RandomAccess.WriteAsync(handle, tempMemory, 0).ConfigureAwait(false);
        }
        finally
        {
            if (tempArray is not null)
            {
                _pool.Return(tempArray);
            }

            semaphore.Release();
        }

        return entries;
    }

    private async Task<List<HashEntry>> GetPwnedPasswordsRangeFromWeb(ReadOnlyMemory<byte> hash, List<HashEntry> items)
    {
        var cloudflareTimer = Stopwatch.StartNew();
        string requestUri = Convert.ToHexString(hash.Span[..3])[..5];
        using HttpResponseMessage response = await _policy.ExecuteAsync(() =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            return _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        }).ConfigureAwait(false);
        Stream content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        await ParseHibpEntriesAsync(requestUri[4], content, items).ConfigureAwait(false);
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

        return items;
    }

    private List<HashEntry> GetHashList()
    {
        if (_hashEntries.TryPop(out List<HashEntry>? items) && items != null)
        {
            items.Clear();
            return items;
        }
        else
        {
            return new List<HashEntry>();
        }
    }

    private static async Task<List<HashEntry>> ParseHibpEntriesAsync(char firstChar, Stream stream, List<HashEntry> entries)
    {
        await foreach (string item in stream.ParseLinesAsync().ConfigureAwait(false))
        {
            if (HashEntry.TryParse(firstChar, item, out HashEntry entry))
            {
                entries.Add(entry);
            }
        }

        return entries;
    }

    private static (bool Exists, int Prevalence) FindPasswordMatch(List<HashEntry> pwnedPasswords, ReadOnlySpan<byte> hashSuffix)
    {
        int index = pwnedPasswords.BinarySearch(new(hashSuffix, 0));
        if (index >= 0)
        {
            return (true, pwnedPasswords[index].Prevalence);
        }

        return (false, 0);
    }

    private async Task ReadPasswords(string inputFile)
    {
        if (_passwords != null)
        {
            using FileStream file = new(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 16384, true);
            int linenum = 0;
            await foreach (string line in file.ParseLinesAsync().ConfigureAwait(false))
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    if(!_passwords.Writer.TryWrite(line))
                    {
                        await _passwords.Writer.WriteAsync(line).ConfigureAwait(false);
                    }
                }
                else
                {
                    AnsiConsole.MarkupLine($"[yellow]Invalid password \"{line.EscapeMarkup()}\" at line {linenum}[/].");
                }

                linenum++;
            }

            _passwords.Writer.Complete();
        }
    }
}
