#include <map>
#include <span>
#include <string>

#include <boost/beast/version.hpp>

#include "request.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace io = boost::asio;

static RangeResults::values_t
to_range_results_values(const http::response<http::dynamic_body> &response)
{
    RangeResults::values_t range_values;

    hexsuffix_t suffix_buffer;
    std::string count_buffer(10, 0);
    std::size_t pos = 0;

    bool parse_count = false;
    for (const auto buffer : response.body().cdata())
    {
        for (const auto c : std::span{
                 reinterpret_cast<const char *>(buffer.data()), buffer.size()})
        {
            if (c == '\n')
            {
                count_buffer[pos] = 0;
                pos = 0;
                range_values[suffix_buffer] = std::stoi(count_buffer);
                parse_count = false;
                continue;
            }
            else if (c == ':')
            {
                pos = 0;
                parse_count = true;
                continue;
            }
            else if (parse_count)
            {
                count_buffer[pos++] = c;
            }
            else
            {
                suffix_buffer[pos++] = c;
            }
        }
    }
    if (pos != 0)
    {
        count_buffer[pos] = 0;
        range_values[suffix_buffer] = std::stoi(count_buffer);
    }

    return range_values;
}

auto const HOST = "api.pwnedpasswords.com";

std::tuple<RangeResults, bool>
request_range(beast::ssl_stream<beast::tcp_stream> &stream,
              const std::string &target, io::yield_context yield,
              beast::error_code &ec)
{
    http::request<http::string_body> req{http::verb::get, target, 11};
    req.set(http::field::host, HOST);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Send the HTTP request to the remote host
    ;
    http::async_write(stream, req, yield[ec]);
    if (ec)
        return std::make_tuple(RangeResults{}, true);

    // Receive the HTTP response
    // response stuff
    beast::flat_buffer buffer;
    http::response<http::dynamic_body> response;
    http::async_read(stream, buffer, response, yield[ec]);
    if (ec)
        return std::make_tuple(RangeResults{}, true);
    if (response.result_int() != 200)
    {
        fmt::print("Status not 200: {}\n", response.result_int());
        return std::make_tuple(RangeResults{}, true);
    }

    bool close_connection = response["Connection"] == "close";
    return std::make_tuple(RangeResults{to_range_results_values(response),
                                        response.payload_size().value()},
                           close_connection);
}

