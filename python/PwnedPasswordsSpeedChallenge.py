import argparse
import hashlib
import os
import pickle
import requests
import threading
import time

class ThreadSafeData:
    def __init__(self):
        self.api_mem_cache = {}
        self.api_mem_cache_lock = threading.Lock()
        self.api_mem_cache_modified = {}
        self.api_mem_cache_modified_lock = threading.Lock()
        self.processed_count = 0
        self.processed_count_lock = threading.Lock()
        self.cf_requests = 0
        self.cf_requests_lock = threading.Lock()
        self.cf_requests_response_time = 0
        self.cf_requests_response_time_lock = threading.Lock()
        self.requests_cached = 0
        self.requests_cached_lock = threading.Lock()
        self.requests_not_cached = 0
        self.requests_not_cached_lock = threading.Lock()
        self.results = []
        self.results_lock = threading.Lock()

def getRangeFile(prefix: str, thread_safe_data: ThreadSafeData, args: argparse.Namespace) -> None:
    api_url = "https://api.pwnedpasswords.com/range/"
    filename = os.path.join("api_storage_cache", f"{prefix}.txt")
    if not os.path.exists(filename):
        while True:
            try:
                local_path = filename
                url = f"{api_url}{prefix}"
                response = requests.get(url, timeout = 10)
                response.raise_for_status()
                with thread_safe_data.cf_requests_lock:
                    thread_safe_data.cf_requests += 1
                with thread_safe_data.cf_requests_response_time_lock:
                    thread_safe_data.cf_requests_response_time += response.elapsed.total_seconds()
                if response.headers["CF-Cache-Status"] == "HIT":
                    with thread_safe_data.requests_cached_lock:
                        thread_safe_data.requests_cached += 1
                else:
                    with thread_safe_data.requests_not_cached_lock:
                        thread_safe_data.requests_not_cached += 1
                with thread_safe_data.api_mem_cache_lock:
                    thread_safe_data.api_mem_cache[prefix] = { prefix + i[0]: i[1] for i in [x.split(":") for x in response.text.splitlines()] }
                with thread_safe_data.api_mem_cache_modified_lock:
                    thread_safe_data.api_mem_cache_modified = True
                break
            except Exception as e:
                print(e)
                continue

def getCount(hash: str, thread_safe_data: ThreadSafeData, args: argparse.Namespace) -> str:
    prefix = hash[:5]
    if not prefix in thread_safe_data.api_mem_cache or args.ignore_cache:
        getRangeFile(prefix, thread_safe_data, args)
    count = thread_safe_data.api_mem_cache[prefix].get(hash, None)
    with thread_safe_data.processed_count_lock:
        thread_safe_data.processed_count += 1
    return count

def threadFunction(block, thread_safe_data, args: argparse.Namespace) -> None:
    for line in block:
        hash = hashlib.sha1(line.encode()).hexdigest().upper()
        count = getCount(hash, thread_safe_data, args)
        if count == None:
            print(f"'{line}' not found in HaveIBeenPwned")
            continue
        with thread_safe_data.results_lock:
            thread_safe_data.results.append(line + "," + count)

def main() -> None:
    thread_safe_data = ThreadSafeData()
    threads = []

    print()

    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help = "File with passwords separated by newlines to be checked")
    parser.add_argument("output_file", help = "File to store the results in csv format")
    parser.add_argument("-t", dest = "thread_count", type = int, help = "Number of threads to be used, defaults to the CPU count", default = os.cpu_count())
    parser.add_argument("-i", dest = "ignore_cache", help = "Don't use the local cache, defaults to false", action = "store_true")
    parser.add_argument("-c", dest = "clear_cache", help = "Clear the local cache before starting, defaults to false", action = "store_true")
    parser.add_argument("-d", dest = "dont_save_cache", help = "Don't save local cache to disk when completed, defaults to false", action = "store_true")
    args = parser.parse_args()

    with open(args.input_file, "r", encoding = "utf-8") as in_file:
        all_lines = in_file.read().splitlines()

    share_size = int(len(all_lines) / args.thread_count)
    blocks = [all_lines[i: i + share_size] for i in range(0, len(all_lines), share_size)]

    if os.path.exists("api_mem_cache.dat") and not args.clear_cache:
        with open("api_mem_cache.dat", "rb") as cache_file:
            thread_safe_data.api_mem_cache = pickle.load(cache_file)

    timer_start = time.perf_counter()
    for block in blocks:
        threads.append(threading.Thread(target = threadFunction, args = (block, thread_safe_data, args)))
        threads[-1].start()

    for i in range(args.thread_count):
        threads[i].join()
    timer_finish = time.perf_counter()

    print(f"Finished processing {thread_safe_data.processed_count} passwords in {round(timer_finish - timer_start, 3)}ms ({round(thread_safe_data.processed_count / (timer_finish - timer_start), 3)} passwords per second).");
    print(f"We made {thread_safe_data.cf_requests} Cloudflare requests (avg response time: {round(thread_safe_data.cf_requests_response_time / (thread_safe_data.cf_requests if thread_safe_data.cf_requests > 0 else 1), 3)}ms). Of those, Cloudflare had already cached {thread_safe_data.requests_cached} requests, and made {thread_safe_data.requests_not_cached} requests to the HaveIBeenPwned origin server.")

    if thread_safe_data.api_mem_cache_modified and not args.dont_save_cache:
        with open("api_mem_cache.dat", "wb") as cache_file:
            pickle.dump(thread_safe_data.api_mem_cache, cache_file)

    with open(args.output_file, "wb") as csv_file:
        csv_file.write("\n".join(thread_safe_data.results).encode())

if __name__ == '__main__':
    main()
