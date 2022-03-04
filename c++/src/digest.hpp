#pragma once

#include <algorithm>
#include <array>
#include <string_view>

#include <fmt/core.h>
#include <openssl/sha.h>

using digest_t = std::array<unsigned char, SHA_DIGEST_LENGTH>;
using hexdigest_t = std::array<char, SHA_DIGEST_LENGTH * 2>;

using hexprefix_t = std::array<char, 5>;
using hexsuffix_t = std::array<char, SHA_DIGEST_LENGTH * 2 - 5>;

class Digest {
  public:
    Digest(std::string_view password)
        : m_digest(get_digest(password)), m_hexdigest(get_hexdigest(m_digest))
    {}

    const hexdigest_t &hexdigest() const { return m_hexdigest; }
    const digest_t &digest() const { return m_digest; }

    template <typename OutputIt> void extract_hex_suffix(OutputIt suffix) const
    {
        std::copy(std::next(m_hexdigest.begin(), 5), m_hexdigest.end(), suffix);
    }

    template <typename OutputIt> void extract_hex_prefix(OutputIt prefix) const
    {
        std::copy(m_hexdigest.begin(), std::next(m_hexdigest.begin(), 5),
                  prefix);
    }

  private:
    static digest_t get_digest(std::string_view password)
    {
        digest_t digest;
        SHA1(reinterpret_cast<const unsigned char *>(password.data()),
             password.size(), digest.data());
        return digest;
    }

    static hexdigest_t get_hexdigest(const digest_t &digest)
    {
        hexdigest_t hex;
        auto hex_output = hex.begin();
        for (std::size_t i = 0; i != digest.size(); i++)
        {
            hex_output = fmt::format_to(hex_output, "{:02X}", digest[i]);
        }
        return hex;
    }

    digest_t m_digest;
    hexdigest_t m_hexdigest;
};
