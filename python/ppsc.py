import argparse
import asyncio
import collections
import functools
import hashlib
import multiprocessing
import pickle
import statistics
import time

import aiohttp
from tqdm import tqdm


class GlobalData:
    def __init__(self, manager):
        self.shared_values = manager.list([0, 0, 0])
        self.lock = manager.Lock()

    def password_checked(self, total_bytes, cloudflare_miss):
        with self.lock:
            self.shared_values[0] += 1
            self.shared_values[1] += total_bytes
            self.shared_values[2] += cloudflare_miss

    def get_passwords_checked(self):
        return self.shared_values[0]

    def get_total_bytes(self):
        return self.shared_values[1]

    def get_cloudflare_misses(self):
        return self.shared_values[2]

    def get_stats(self):
        with self.lock:
            return self.shared_values[0], self.shared_values[1], self.shared_values[2]


async def request_range(session, prefix):
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    start = time.time()
    async with session.get(url) as response:
        if response.status != 200:
            raise ValueError(await response.read())
        cloudflare_miss = response.headers["CF-Cache-Status"] == "MISS"
        response = await response.read()
        end = time.time()
        return response, cloudflare_miss, end - start


async def get_count(password, session, cache):
    digest = hashlib.sha1(password).hexdigest().upper()
    prefix = digest[:5]
    suffix = digest[5:]

    total_bytes = 0
    cloudflare_miss = False
    duration = 0
    if prefix not in cache:
        response, cloudflare_miss, duration = await request_range(session, prefix)
        total_bytes = len(response)
        prefix_results = {}
        for line in response.splitlines():
            suffix_candidate, count = line.split(b":")
            prefix_results[suffix_candidate.decode("ascii")] = int(count)
        cache[prefix] = prefix_results

    count = cache[prefix].get(suffix, 0)
    return count, total_bytes, cloudflare_miss, duration


async def get_counts(session, queue, counts, cache, global_data):

    while not queue.empty():
        try:
            password = await queue.get()
        except asyncio.CancelledError:
            return
        else:
            count, total_bytes, cloudflare_miss, duration = await get_count(
                password, session, cache
            )
            counts[password] = (count, duration)
            global_data.password_checked(total_bytes, cloudflare_miss)
        queue.task_done()


async def process_passwords_async(
    loop, passwords, max_requests_in_flight, cache, global_data
):

    counts = {password: 0 for password in passwords}
    queue = asyncio.Queue()
    for password in passwords:
        queue.put_nowait(password)

    async with aiohttp.ClientSession() as session:

        tasks = [
            loop.create_task(get_counts(session, queue, counts, cache, global_data))
            for _ in range(max_requests_in_flight)
        ]
        await queue.join()

        # Cancel and gather now
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks)

    return counts, cache


def process_passwords(passwords, max_requests_in_flight, cache, global_data):
    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            process_passwords_async(
                loop, passwords, max_requests_in_flight, cache, global_data
            )
        )
        loop.close()
        return result
    except Exception as e:
        print(e)
        raise


def monitor_progress(total_passwords, global_data):
    with tqdm(total=total_passwords, unit="req") as progress:

        last_reading = 0

        while last_reading < total_passwords:
            time.sleep(0.2)
            reading, _, cloudflare_misses = global_data.get_stats()
            progress.set_postfix(cloudflare_misses=cloudflare_misses, refresh=False)
            progress.update(reading - last_reading)
            last_reading = reading
        progress.close()


def read_passwords(passwords_file):
    with open(passwords_file, "rb") as f:
        passwords = [password.strip() for password in f]
        password_counts = collections.Counter(passwords)
        diff = len(passwords) - len(password_counts)
        if diff:
            print(
                f"Input file has {diff} duplicate passwords (out of {len(passwords)}):"
            )
            for password, count in password_counts.items():
                if count > 1:
                    print(f'  "{password.decode("utf-8")}" found {count} times')
            print()
        passwords = list(password_counts)
    return passwords


def merged(dicts):
    result = {}
    for d in dicts:
        result.update(d)
    return result


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("passwords_file", help="input passwords file")
    parser.add_argument(
        "-r",
        "--max-requests-in-flight",
        type=int,
        help="maximum number of requests in flight per thread",
        default=100,
    )
    parser.add_argument(
        "-j", "--jobs", type=int, help="number of jobs to use", default=1
    )
    parser.add_argument(
        "-o", "--output-file", help="csv output filename", default="output.csv"
    )
    parser.add_argument(
        "-c",
        "--cache-file",
        help="file used to load/dump the cache from/to",
        default="pass.cache",
    )
    parser.add_argument(
        "-l",
        "--load-cache",
        action="store_true",
        help="whether to load the cache file at the start",
    )
    parser.add_argument(
        "-d",
        "--dump-cache",
        action="store_true",
        help="whether to dump the cache file at the end",
    )
    args = parser.parse_args()

    start = time.time()
    passwords = read_passwords(args.passwords_file)
    n_passwords = len(passwords)
    print(f"Read {n_passwords} passwords in {time.time() - start:.3f} [s]")

    manager = multiprocessing.Manager()
    global_data = GlobalData(manager)
    pool = multiprocessing.Pool(args.jobs)

    chunk_size = (n_passwords + args.jobs - 1) // args.jobs
    password_chunks = [
        passwords[i : i + chunk_size] for i in range(0, n_passwords, chunk_size)
    ]

    cache = {}
    if args.load_cache:
        with open(args.cache_file, "rb") as f:
            cache = pickle.load(f)

    with pool:
        result = pool.map_async(
            functools.partial(
                process_passwords,
                max_requests_in_flight=args.max_requests_in_flight,
                cache=cache,
                global_data=global_data,
            ),
            password_chunks,
        )

        start = time.time()
        try:
            monitor_progress(n_passwords, global_data)
            end = time.time()
        except KeyboardInterrupt:
            end = time.time()
            return
        else:
            print("Collecting results...")
            result = result.get()
            password_counts, cache = zip(*result)
            password_counts, cache = merged(password_counts), merged(cache)
        finally:
            duration = end - start
            print(
                f"Ran in {duration:.3f} [s], received data at {global_data.get_total_bytes() / 1024 / 1024 / duration:.3f} [MB/s]"
            )

    hits = sum(count[0] > 0 for count in password_counts.values())
    misses = n_passwords - hits
    durations = [count[1] for count in password_counts.values()]
    print(
        f"{hits} hits ({hits * 100 / n_passwords:.2f}%), {misses} misses ({misses * 100 / n_passwords:.2f}%), {len(password_counts)} passwords checked"
    )
    ms = lambda duration: f"{duration * 1000:.3f} [ms]"
    print(
        "Request durations: "
        f" avg: {ms(statistics.mean(durations))}, "
        f" median: {ms(statistics.median(durations))}, "
        f" max: {ms(max(durations))}, "
        f" min: {ms(min(durations))}"
    )

    with open(args.output_file, "wt", encoding="utf-8") as f:
        start = time.time()
        for password, count in password_counts.items():
            f.write(f'{password.decode("utf-8")}, {count[0]}\n')
        print(f"Saved results to {args.output_file} in {time.time() - start:.3f} [s]")
    if misses:
        print("Passwords without hits:")
        for password, count in password_counts.items():
            if count[0] == 0:
                print(f'  "{password.decode("utf-8")}"')

    if args.dump_cache:
        start = time.time()
        with open(args.cache_file, "wb") as f:
            pickle.dump(cache, f)
        print(f"Saved cache to {args.cache_file} in {time.time() - start:.3f} [s]")


if __name__ == "__main__":
    main()
