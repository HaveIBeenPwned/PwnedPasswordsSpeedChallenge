#pragma once

#include <map>
#include <tuple>

#include <boost/asio/spawn.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include "digest.hpp"

struct RangeResults
{
    using values_t = std::map<hexsuffix_t, int>;
    values_t values;
    std::size_t body_size = 0;
};

std::tuple<RangeResults, bool>
request_range(boost::beast::ssl_stream<boost::beast::tcp_stream> &stream,
              const std::string &target, boost::asio::yield_context yield,
              boost::beast::error_code &ec);
