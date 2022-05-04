#pragma once

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <boost/asio/ssl.hpp>

namespace io = boost::asio;
namespace ssl = io::ssl;

inline void load_root_certificates(ssl::context &ctx)
{
    std::ostringstream cert_buffer;
    constexpr auto CERTS_PATH = "/etc/ssl/certs";
    for (const auto &entry : std::filesystem::directory_iterator(CERTS_PATH))
    {
        if (!entry.path().string().ends_with(".pem"))
        {
            continue;
        }
        std::ifstream cert_data(entry.path());
        std::stringstream buffer;
        cert_buffer << cert_data.rdbuf();
    }

    boost::system::error_code ec;
    auto cert = cert_buffer.str();
    ctx.add_certificate_authority(io::buffer(cert.data(), cert.size()), ec);
    if (ec)
        throw boost::system::system_error{ec};
}
