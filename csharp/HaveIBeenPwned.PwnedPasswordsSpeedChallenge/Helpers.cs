// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

using Spectre.Console;

namespace HaveIBeenPwned.PwnedPasswordsSpeedChallenge
{
    internal static class Helpers
    {
        private static readonly Encoding s_encoding = Encoding.UTF8;

        internal static bool TryReadLine(ref ReadOnlySequence<byte> buffer, bool isComplete, out string? line)
        {
            while (buffer.Length > 0)
            {
                SequencePosition? position = buffer.PositionOf((byte)'\n');
                if (position.HasValue)
                {
                    ReadOnlySequence<byte> slice = buffer.Slice(buffer.Start, position.Value);
                    int sliceLength = (int)slice.Length;
                    buffer = buffer.Slice(sliceLength + 1);
                    line = s_encoding.GetString(slice.Slice(0, sliceLength)).Trim();
                    return true;
                }
                else if (isComplete)
                {
                    // The pipe is complete but we don't have a newline character, this input probably ends without a newline char.
                    line = s_encoding.GetString(buffer).Trim();
                    buffer = buffer.Slice(buffer.End, 0);
                    return true;
                }
                else
                {
                    break;
                }
            }

            line = "";
            return false;
        }

        [SkipLocalsInit]
        internal static unsafe void GetSha1Hash(this string password, Memory<byte> hashBytes)
        {
            Span<byte> workSpan = stackalloc byte[1024];
            SHA1.HashData(workSpan.Slice(0, s_encoding.GetBytes(password, workSpan)), hashBytes.Span);
        }

        internal static int CountLines(string inputFile)
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

        internal static async IAsyncEnumerable<string> ReadLinesAsync<T>(this T pipeReader) where T : PipeReader
        {
            while (true)
            {
                if (!pipeReader.TryRead(out ReadResult result))
                {
                    await pipeReader.ReadAsync().ConfigureAwait(false);
                }

                if (result.Buffer.IsEmpty && result.IsCompleted)
                {
                    break;
                }

                ReadOnlySequence<byte> buffer = result.Buffer;
                while (TryReadLine(ref buffer, result.IsCompleted, out string? line))
                {
                    if (line != null)
                    {
                        yield return line;
                    }
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }
        }

        internal static async IAsyncEnumerable<string> ParseLinesAsync<T>(this T stream, int pauseThreshold = 1024 * 64, int resumeThreshold = 1024 * 32) where T : Stream
        {
            var inputPipe = new Pipe(new PipeOptions(pauseWriterThreshold: pauseThreshold, resumeWriterThreshold: resumeThreshold, useSynchronizationContext: false));
            Task copyTask = stream.CopyToAsync(inputPipe.Writer).ContinueWith(CompleteWriter, inputPipe.Writer).Unwrap();

            await foreach (string line in inputPipe.Reader.ReadLinesAsync())
            {
                yield return line;
            }

            await copyTask.ConfigureAwait(false);
        }

        internal static async Task CompleteWriter(Task previousTask, object? state)
        {
            if (previousTask.IsCompleted && state is PipeWriter pipeWriter)
            {
                await pipeWriter.FlushAsync().ConfigureAwait(false);
                await pipeWriter.CompleteAsync().ConfigureAwait(false);
            }
        }
    }
}
