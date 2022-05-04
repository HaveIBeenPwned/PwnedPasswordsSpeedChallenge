#pragma once

#include <map>
#include <mutex>
#include <shared_mutex>
#include <utility>

#include <boost/container/flat_map.hpp>

#include "digest.hpp"
#include "request.hpp"

class Cache {

  public:
    enum class EntryStatus
    {
        ValueCached,
        PrefixCached,
        Uncached
    };

	 virtual ~Cache() = default;

    virtual std::pair<EntryStatus, std::size_t> get(const Digest &digest) const = 0;
    virtual void put(hexprefix_t prefix, const RangeResults::values_t &results) = 0;

	 std::size_t prefix_hits() const { return m_prefix_hits; }
	 std::size_t full_hits() const { return m_full_hits; }

  protected:
	 mutable std::size_t m_prefix_hits {0};
	 mutable std::size_t m_full_hits {0};
};

class HexCache : public Cache {

  public:
    std::pair<Cache::EntryStatus, std::size_t> get(const Digest &digest) const
    {
        hexprefix_t prefix;
        hexsuffix_t suffix;
        digest.extract_hex_prefix(prefix.begin());
        digest.extract_hex_suffix(suffix.begin());
        {
            auto _lock = std::shared_lock{m_access_mutex};
            auto prefix_values = m_cache.find(prefix);
            if (prefix_values == m_cache.end())
            {
                return {Cache::EntryStatus::Uncached, 0};
            }
            ++m_prefix_hits;
            auto value = prefix_values->second.find(suffix);
            if (value == prefix_values->second.end())
            {
                return {Cache::EntryStatus::PrefixCached, 0};
            }
            ++m_full_hits;
            return {Cache::EntryStatus::ValueCached, value->second};
        }
    }

    void put(hexprefix_t prefix, const RangeResults::values_t &values)
    {
        boost::container::flat_map<hexsuffix_t, int> flat_values(boost::container::ordered_unique_range, values.begin(), values.end());
		  {
           auto _lock = std::unique_lock{m_access_mutex};
           m_cache[prefix] = std::move(flat_values);
		  }
    }

  private:
    mutable std::shared_mutex m_access_mutex;
    std::map<hexprefix_t, boost::container::flat_map<hexsuffix_t, int>> m_cache;
};

class NullCache : public Cache {

  public:
    std::pair<Cache::EntryStatus, std::size_t> get(const Digest &digest) const
    {
        return {Cache::EntryStatus::Uncached, 0};
    }

    void put(hexprefix_t prefix, const RangeResults::values_t &results)
    {
    }
};
