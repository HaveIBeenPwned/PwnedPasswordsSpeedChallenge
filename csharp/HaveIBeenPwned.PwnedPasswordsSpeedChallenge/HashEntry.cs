// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;

namespace HaveIBeenPwned.PwnedPasswordsSpeedChallenge
{
    internal readonly struct HashEntry : IComparable<HashEntry>
    {
        internal readonly ulong _highBytes;
        internal readonly ulong _midBytes;
        internal readonly ushort _lowBytes;
        internal readonly uint _prevalence;
        internal int Prevalence => (int)_prevalence;

        internal HashEntry(ReadOnlySpan<byte> hashBytes, int prevalence)
        {
            if (hashBytes.Length == 18)
            {
                _highBytes = BinaryPrimitives.ReadUInt64BigEndian(hashBytes.Slice(0, 8));
                _midBytes = BinaryPrimitives.ReadUInt64BigEndian(hashBytes.Slice(8, 8));
                _lowBytes = BinaryPrimitives.ReadUInt16BigEndian(hashBytes.Slice(16, 2));
                _prevalence = (uint)prevalence;
            }
            else
            {
                throw new ArgumentException($"{nameof(hashBytes)} does not contains 18 bytes of data.");
            }
        }

        private HashEntry(ReadOnlySpan<byte> hashBytes)
        {
            BinaryPrimitives.TryReadUInt64BigEndian(hashBytes, out _highBytes);
            BinaryPrimitives.TryReadUInt64BigEndian(hashBytes.Slice(8), out _midBytes);
            BinaryPrimitives.TryReadUInt16BigEndian(hashBytes.Slice(16), out _lowBytes);
            BinaryPrimitives.TryReadUInt32BigEndian(hashBytes.Slice(18), out _prevalence);
        }

        public int CompareTo(HashEntry other)
        {
            int result = _highBytes.CompareTo(other._highBytes);
            if (result == 0)
            {
                result = _midBytes.CompareTo(other._midBytes);
                if (result == 0)
                {
                    result = _lowBytes.CompareTo(other._lowBytes);
                }
            }

            return result;
        }

        public bool TryWrite(Span<byte> span)
        {
            if (span.Length < 22)
            {
                return false;
            }

            BinaryPrimitives.TryWriteUInt64BigEndian(span, _highBytes);
            BinaryPrimitives.TryWriteUInt64BigEndian(span.Slice(8), _midBytes);
            BinaryPrimitives.TryWriteUInt16BigEndian(span.Slice(16), _lowBytes);
            BinaryPrimitives.TryWriteUInt32BigEndian(span.Slice(18), _prevalence);

            return true;
        }

        internal static bool TryParse(ReadOnlySpan<char> chars, out HashEntry entry)
        {
            if (chars.Length >= 37)
            {
                int colonIndex = chars.IndexOf(':');
                if (colonIndex == 36)
                {
                    Span<byte> hashBytes = stackalloc byte[18];

                    for (int i = 0; i < 18; i++)
                    {
                        hashBytes[i] = (byte)((HexCharToByte(chars[i * 2]) << 4) | HexCharToByte(chars[i * 2 + 1]));
                    }

                    if (int.TryParse(chars.Slice(colonIndex+1), out int prevalence))
                    {
                        entry = new HashEntry(hashBytes, prevalence);
                        return true;
                    }
                }
            }

            entry = default;
            return false;
        }

        internal static bool TryRead(Span<byte> span, out HashEntry entry)
        {
            if (span.Length >= 22)
            {
                entry = new HashEntry(span);
                return true;
            }

            entry = default;
            return false;
        }

        public bool Equals(HashEntry other) => _highBytes == other._highBytes && _midBytes == other._midBytes && _lowBytes == other._lowBytes;

        internal static byte HexCharToByte(char hexChar) => hexChar switch
        {
            >= (char)48 and <= (char)57 => (byte)(hexChar - 48),
            >= (char)65 and <= (char)70 => (byte)(hexChar - 55),
            >= (char)97 and <= (char)102 => (byte)(hexChar - 87),
            _ => 0,
        };
    }
}
