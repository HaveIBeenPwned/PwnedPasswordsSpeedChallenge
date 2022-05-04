#pragma once

#include <chrono>
#include <string>

#include <fmt/core.h>

class Timer {

  public:
    using clock = std::chrono::high_resolution_clock;
    using duration = typename std::chrono::milliseconds::rep;

    /**
     * Returns the number of milliseconds elapsed since the creation
     * of the timer
     *
     * @return The time elapsed since the creation of the timer, in [ms]
     */
    inline duration get_millis() const
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   clock::now() - t0)
            .count();
    }

    std::string get_fmt() const { return format(get_millis()); }

    static std::string format(duration millis)
    {
        if (millis < 1000)
        {
            return fmt::format("{} [ms]", millis);
        }
        return fmt::format("{} [s]", millis / 1000.f);
    }

  private:
    clock::time_point t0{clock::now()};
};
