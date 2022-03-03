// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace HaveIBeenPwned.PwnedPasswordsSpeedChallenge
{
    public sealed class AsyncDuplicateLock
    {
        private sealed class CountedValue<T>
        {
            public CountedValue(T value) => Value = value;

            public int Count { get; set; } = 1;
            public T Value { get; }
        }

        private static readonly Dictionary<object, CountedValue<SemaphoreSlim>> s_semaphores = new();

        private static SemaphoreSlim GetOrCreate(object key)
        {
            lock (s_semaphores)
            {
                if (s_semaphores.TryGetValue(key, out CountedValue<SemaphoreSlim> item))
                {
                    ++item.Count;
                }
                else
                {
                    item = new CountedValue<SemaphoreSlim>(new SemaphoreSlim(1, 1));
                    s_semaphores[key] = item;
                }

                return item.Value;
            }
        }

        public static IDisposable Lock(object key)
        {
            GetOrCreate(key).Wait();
            return new Releaser(key);
        }

        public static Task<IDisposable> LockAsync(object key)
        {
            SemaphoreSlim item = GetOrCreate(key);
            return !item.Wait(0) ? LockAsyncImpl(item, key) : Task.FromResult<IDisposable>(new Releaser(key));
        }

        private static async Task<IDisposable> LockAsyncImpl(SemaphoreSlim item, object key)
        {
            await item.WaitAsync().ConfigureAwait(false);
            return new Releaser(key);
        }

        private sealed class Releaser : IDisposable
        {
            public Releaser(object key) => Key = key;

            public object Key { get; }

            public void Dispose()
            {
                CountedValue<SemaphoreSlim> item;
                lock (s_semaphores)
                {
                    item = s_semaphores[Key];
                    --item.Count;
                    if (item.Count == 0)
                    {
                        s_semaphores.Remove(Key);
                    }
                }

                item.Value.Release();
            }
        }
    }
}
