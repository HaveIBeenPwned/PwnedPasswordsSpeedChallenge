using System.Buffers;
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
    internal AsyncDuplicateLock _duplicateLock = new();
    internal ConcurrentStack<List<HashEntry>> _hashEntries = new();

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

        _passwords = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = false, SingleWriter = true });
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
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls13;
        }

        HttpClient client = new(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/range/"), DefaultRequestVersion = HttpVersion.Version30 };
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

            byte[] array = ArrayPool<byte>.Shared.Rent(16384);
            Memory<byte> memory = array.AsMemory(0, 16384);
            using SafeFileHandle handle = File.OpenHandle(outputFile, FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.Asynchronous);
            int offset = 0;
            while (await _results.Reader.WaitToReadAsync().ConfigureAwait(false))
            {
                int totalBytes = 0;
                while (_results.Reader.TryRead(out string line))
                {
                    int byteCount = s_encoding.GetByteCount(line) + 2;
                    if ((totalBytes + byteCount) > memory.Length)
                    {
                        ValueTask writeTask = RandomAccess.WriteAsync(handle, memory.Slice(0, totalBytes), offset);
                        if(!writeTask.IsCompletedSuccessfully)
                        {
                            await writeTask.ConfigureAwait(false);
                        }

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
                    ValueTask writeTask = RandomAccess.WriteAsync(handle, memory.Slice(0, totalBytes), offset);
                    if (!writeTask.IsCompletedSuccessfully)
                    {
                        await writeTask.ConfigureAwait(false);
                    }

                    offset += totalBytes;
                }
            }

            ArrayPool<byte>.Shared.Return(array);
        }
    }

    private async Task ProcessPassword(Settings settings)
    {
        if (_passwords != null && _results != null)
        {
            byte[] hashBytes = ArrayPool<byte>.Shared.Rent(20);
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

            ArrayPool<byte>.Shared.Return(hashBytes);
        }
    }

    private async Task<List<HashEntry>> GetPwnedPasswordsRange(ReadOnlyMemory<byte> hash, bool skipCache)
    {
        List<HashEntry> entries = GetHashList();

        if (skipCache)
        {
            return await GetPwnedPasswordsRangeFromWeb(hash, entries).ConfigureAwait(false);
        }

        string prefixFile = Path.Combine(_cacheDir, $"{Convert.ToHexString(hash.Span[..3])[..5]}.txt");

        using (await AsyncDuplicateLock.LockAsync(string.Intern(prefixFile)).ConfigureAwait(false))
        {
            try
            {
                using SafeFileHandle? handle = File.OpenHandle(prefixFile, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.SequentialScan | FileOptions.Asynchronous);
                int numEntries = (int)RandomAccess.GetLength(handle) / 22;
                byte[] tempArray = ArrayPool<byte>.Shared.Rent(numEntries * 22);
                Memory<byte> tempMemory = tempArray.AsMemory(0, numEntries * 22);
                ValueTask<int> readTask = RandomAccess.ReadAsync(handle, tempMemory, 0);
                if (!readTask.IsCompletedSuccessfully)
                {
                    await readTask.ConfigureAwait(false);
                }

                for (int i = 0; i < numEntries; i++)
                {
                    int index = i * 22;
                    if (HashEntry.TryRead(tempMemory.Span.Slice(index, 22), out HashEntry entry))
                    {
                        entries.Add(entry);
                    }
                }

                ArrayPool<byte>.Shared.Return(tempArray);
            }
            catch (FileNotFoundException)
            {
                await GetPwnedPasswordsRangeFromWeb(hash, entries).ConfigureAwait(false);
                int totalBytes = entries.Count * 22;
                using SafeFileHandle handle = File.OpenHandle(prefixFile, FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.Asynchronous, totalBytes);
                byte[] tempArray = ArrayPool<byte>.Shared.Rent(totalBytes);
                Memory<byte> tempMemory = tempArray.AsMemory(0, totalBytes);
                for (int i = 0; i < entries.Count; i++)
                {
                    int index = i * 22;
                    entries[i].TryWrite(tempMemory.Span.Slice(index, 22));
                }

                ValueTask writeTask = RandomAccess.WriteAsync(handle, tempMemory, 0);
                if (!writeTask.IsCompletedSuccessfully)
                {
                    await writeTask.ConfigureAwait(false);
                }

                ArrayPool<byte>.Shared.Return(tempArray);
            }
        }

        return entries;
    }

    private async Task<List<HashEntry>> GetPwnedPasswordsRangeFromWeb(ReadOnlyMemory<byte> hash, List<HashEntry> items)
    {
        var cloudflareTimer = Stopwatch.StartNew();
        using var request = new HttpRequestMessage(HttpMethod.Get, Convert.ToHexString(hash[..3].Span)[..5]);
        using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        Stream content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        await ParseHibpEntriesAsync(Convert.ToHexString(hash.Span.Slice(2, 1))[0], content, items).ConfigureAwait(false);
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
        if (_hashEntries.TryPop(out List<HashEntry> items))
        {
            items.Clear();
        }
        else
        {
            items = new List<HashEntry>();
        }

        return items;
    }

    private static async Task<List<HashEntry>> ParseHibpEntriesAsync(char firstChar, Stream stream, List<HashEntry> entries)
    {
        char[] charArray = ArrayPool<char>.Shared.Rent(64);
        Memory<char> chars = charArray.AsMemory(0, 64);
        chars.Span[0] = firstChar;
        await foreach (string item in stream.ParseLinesAsync().ConfigureAwait(false))
        {
            item.CopyTo(chars.Span.Slice(1));
            if (HashEntry.TryParse(chars.Span.Slice(0, item.Length + 1), out HashEntry entry))
            {
                entries.Add(entry);
            }
        }

        ArrayPool<char>.Shared.Return(charArray);

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
                    _passwords.Writer.TryWrite(line);
                }
                else
                {
                    AnsiConsole.MarkupLine($"[yellow]Invalid password \"{line}\" at line {linenum}[/].");
                }

                linenum++;
            }

            _passwords.Writer.Complete();
        }
    }
}
