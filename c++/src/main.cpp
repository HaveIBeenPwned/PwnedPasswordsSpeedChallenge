#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <numeric>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/program_options.hpp>
#include <fmt/core.h>
#include <fmt/os.h>

#include "cache.hpp"
#include "digest.hpp"
#include "password.hpp"
#include "progress.hpp"
#include "request.hpp"
#include "root_certificates.hpp"
#include "timer.hpp"

namespace beast = boost::beast;
namespace io = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = io::ip::tcp;

auto const HOST = "api.pwnedpasswords.com";

auto get_passwords_count(
    io::io_context &ioc, ssl::context &ctx,
    const tcp::resolver::results_type &pwned_passwords_endpoint,
    std::span<Password> passwords, std::size_t &current_password_index,
    Progress &progress, Cache &cache, std::size_t timeout, bool dry_run,
    io::yield_context yield)
{
    auto fail = [](beast::error_code ec, char const *what)
    { std::cerr << what << ": " << ec.message() << "\n"; };

    auto get_stream = [pwned_passwords_endpoint, timeout, dry_run, &ioc,
                       &ctx](beast::error_code &ec, io::yield_context yield)
    {
        auto stream =
            std::make_unique<beast::ssl_stream<beast::tcp_stream>>(ioc, ctx);
        if (timeout > 0)
        {
            get_lowest_layer(*stream).expires_after(
                std::chrono::milliseconds(timeout));
        }
        if (!dry_run)
        {
            get_lowest_layer(*stream).async_connect(pwned_passwords_endpoint,
                                                    yield[ec]);
            if (ec)
                return stream;
            // SSL handshake
            stream->async_handshake(ssl::stream_base::client, yield[ec]);
            if (ec)
                return stream;
        }
        else
        {
            ioc.post(yield);
        }
        return stream;
    };

    auto close_stream =
        [&](std::unique_ptr<beast::ssl_stream<beast::tcp_stream>> &stream,
            beast::error_code &ec)
    {
        // Gracefully close the socket
        if (!dry_run)
        {
            stream->async_shutdown(yield[ec]);
            if (ec == ssl::error::stream_truncated)
            {
                get_lowest_layer(*stream).close();
                ec = {};
            }
            else if (ec == io::error::eof)
            {
                ec = {};
            }
        }
        else
        {
            ioc.post(yield);
        }
    };

    beast::error_code ec;

    // Make the connection on the IP address we get from a lookup
    auto stream = get_stream(ec, yield);
    if (ec)
    {
        return fail(ec, "get_stream");
    }

    std::string target = "/range/XXXXX";

    while (true)
    {
        if (progress.interrupted())
        {
            break;
        }
        if (current_password_index == passwords.size())
        {
            break;
        }

        assert(current_password_index < passwords.size());
        auto &password = passwords[current_password_index];
        current_password_index++;

        std::size_t body_size = 0;
        std::size_t count = 0;

        Digest digest(password.value);
        auto [status, value] = cache.get(digest);
        if (status == Cache::EntryStatus::ValueCached ||
            status == Cache::EntryStatus::PrefixCached)
        {
            count = value;
        }
        else
        {
            hexprefix_t prefix;
            hexsuffix_t suffix;
            digest.extract_hex_prefix(prefix.begin());
            digest.extract_hex_prefix(std::next(target.end(), -5));
            digest.extract_hex_suffix(suffix.begin());

            if (!dry_run)
            {
                auto [range_results, close_connection] =
                    request_range(*stream, target, yield, ec);
                if (ec)
                {
                    if (ec == beast::error::timeout)
                        progress.add_request_time_out();
                    else
                        progress.add_request_error();
                }
                else
                    cache.put(prefix, range_results.values);

                if (close_connection)
                {
                    progress.add_connection_reset();
                    close_stream(stream, ec);
                    stream = get_stream(ec, yield);
                    if (ec)
                    {
                        fail(ec, "get_stream");
                    }
                }

                count = [&]()
                {
                    auto found = range_results.values.find(suffix);
                    if (found == range_results.values.end())
                    {
                        return 0;
                    }
                    return found->second;
                }();

                body_size = range_results.body_size;
            }
            else
            {
                ioc.post(yield);
            }
        }

        password.count = count;
        password.checked = true;
        progress.password_checked(body_size);
    }

    close_stream(stream, ec);
    if (ec)
    {
        return fail(ec, "close_stream");
    }
}

void do_monitoring(io::io_context &ioc, Progress &progress,
                   io::signal_set &signals_handler, io::yield_context yield)
{
    io::deadline_timer timer(ioc);
    while (!progress.update_progress_bar())
    {
        if (progress.interrupted())
        {
            progress.mark_as_completed();
            break;
        }
        timer.expires_from_now(boost::posix_time::milliseconds(200));
        timer.async_wait(yield);
    }
    signals_handler.cancel();
}

void password_counting_thread(ssl::context &ctx, std::span<Password> passwords,
                              int workers, Progress &progress, Cache &cache,
                              std::size_t timeout, bool dry_run)
{
    io::io_context ioc;
    std::size_t current_password_index = 0;
    io::spawn(ioc,
              [&](io::yield_context yield)
              {
                  auto fail = [](beast::error_code ec, char const *what)
                  { std::cerr << what << ": " << ec.message() << "\n"; };

                  // Look up the domain name
                  tcp::resolver::results_type pwned_passwords_endpoint;
                  if (!dry_run)
                  {
                      tcp::resolver resolver(ioc);
                      beast::error_code ec;
                      pwned_passwords_endpoint =
                          resolver.async_resolve(HOST, "443", yield[ec]);
                      if (ec)
                      {
                          return fail(ec, "resolve");
                      }
                  }
                  else
                  {
                      ioc.post(yield);
                  }

                  // Launch the asynchronous operation
                  for (int i = 0; i != workers; i++)
                  {
                      io::spawn(ioc,
                                [&](io::yield_context yield)
                                {
                                    get_passwords_count(
                                        ioc, ctx, pwned_passwords_endpoint,
                                        passwords, current_password_index,
                                        progress, cache, timeout, dry_run,
                                        yield);
                                });
                  }
              });

    ioc.run();
}

struct Options
{
    std::string password_filename;
    std::size_t n_workers;
    std::size_t n_threads;
    std::string output_filename;
    std::size_t timeout;
    bool dry_run;
    bool no_cache;
};

auto parse_options(int argc, char *argv[])
{
    Options options;
    namespace po = boost::program_options;
    po::options_description desc("Allowed options");
    po::positional_options_description positional;
    positional.add("password_file", 1);
    desc.add_options()("help,h", "show this help message")(
        "threads,t",
        po::value<std::size_t>(&options.n_threads)->default_value(1),
        "number of threads to use")(
        "workers,w",
        po::value<std::size_t>(&options.n_workers)->default_value(1),
        "number of concurrent workers per thread")(
        "password_file", po::value<std::string>(&options.password_filename),
        "passwords input file")("output_file,o",
                                po::value<std::string>(&options.output_filename)
                                    ->default_value("output.csv"),
                                "output CSV filename")(
        "timeout,T", po::value<std::size_t>(&options.timeout)->default_value(0),
        "requests timeout in milliseconds (0 = no timeout)")(
        "dry-run,d", "Dry-run (no network access)")("no-cache,C",
                                                    "Don't use a cache");

    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv)
                  .options(desc)
                  .positional(positional)
                  .run(),
              vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        std::cout << desc << '\n';
        exit(EXIT_SUCCESS);
    }
    else if (vm.count("password_file") == 0)
    {
        throw po::error("At least one <password_file> option must be given. "
                        "Use -h to see the help");
    }

    options.dry_run = vm.count("dry-run") > 0;
    options.no_cache = vm.count("no-cache") > 0;
    return options;
}

int main(int argc, char *argv[])
{
    auto options = parse_options(argc, argv);

    auto passwords = read_passwords(options.password_filename);

    io::io_context ioc;

    // SSL context that holds certificates
    ssl::context ctx{ssl::context::tlsv12_client};
    load_root_certificates(ctx);
    ctx.set_verify_mode(ssl::verify_peer);

    Progress progress{passwords.size()};
    auto cache = [&]() -> std::unique_ptr<Cache>
    {
        if (options.no_cache)
        {
            return std::make_unique<NullCache>();
        }
        return std::make_unique<HexCache>();
    }();

    // Start an asynchronous wait for one of the signals to occur.
    io::signal_set signals_handler(ioc, SIGINT, SIGTERM);
    signals_handler.async_wait(
        [&progress](const boost::system::error_code &error, int signal_number)
        { progress.interrupt(); });

    Timer timer;
    std::vector<std::thread> threads;
    auto passwords_span = std::span{passwords};
    std::size_t chunk_size =
        (passwords.size() + options.n_threads - 1) / options.n_threads;
    std::size_t remainder = passwords.size();
    for (int i = 0; i != options.n_threads; i++)
    {
        auto passwords_for_thread = passwords_span.subspan(
            chunk_size * i, std::min(chunk_size, remainder));
        remainder -= passwords_for_thread.size();
        auto entrypoint =
            [passwords_for_thread, &options, &ctx, &progress, &cache]()
        {
            password_counting_thread(ctx, passwords_for_thread,
                                     options.n_workers, progress, *cache,
                                     options.timeout, options.dry_run);
        };
        threads.push_back(std::thread{entrypoint});
    }
    assert(remainder == 0);

    io::spawn(ioc,
              [&progress, &ioc, &signals_handler](auto yield_context) {
                  do_monitoring(ioc, progress, signals_handler, yield_context);
              });

    // Run the I/O service. The call will return when
    // the get operation is complete.
    ioc.run();

    for (auto &thread : threads)
    {
        thread.join();
    }

    auto duration = timer.get_millis();
    auto passwords_checked = progress.passwords_checked();
    fmt::print("Processed {} passwords in {} at {:.2f} req/s, {:.2f} MB/s\n",
               passwords_checked, Timer::format(duration),
               passwords_checked * 1000.f / duration,
               progress.bytes_downloaded() / 1024.f / 1024.f / duration *
                   1000.f);
    fmt::print(
        "Cache hits: prefix={} ({:.2f}%), full={} ({:.2f}%)\n",
        cache->prefix_hits(), cache->prefix_hits() * 100.f / passwords_checked,
        cache->full_hits(), cache->full_hits() * 100.f / passwords_checked);

    write_results(passwords, options.output_filename);

    return EXIT_SUCCESS;
}
