#pragma once

#include <atomic>
#include <chrono>

#include "indicators.hpp"

class Progress {
  public:
    Progress(std::size_t total_passwords);
    ~Progress();

    void password_checked(std::size_t bytes_downloaded)
    {
        ++m_passwords_checked;
        m_bytes_downloaded += bytes_downloaded;
    }

    void add_request_error() { ++m_requests_errored; }
    void add_request_time_out() { ++m_requests_timed_out; }
    void add_connection_reset() { ++m_connections_reset; }

    std::size_t requests_errored() { return m_requests_errored; }
    std::size_t requests_timed_out() { return m_requests_timed_out; }
    std::size_t connections_reset() { return m_connections_reset; }

    std::size_t bytes_downloaded() { return m_bytes_downloaded; }

    std::size_t passwords_checked() { return m_passwords_checked; }

    void mark_as_completed() { m_progress_bar.mark_as_completed(); }

    bool update_progress_bar();

    void interrupt() { m_interrupt_set = true; }

    bool interrupted() const { return m_interrupt_set.load(); }

  private:
    std::size_t m_total_passwords;
    indicators::ProgressBar m_progress_bar;
    std::atomic<std::size_t> m_passwords_checked{0};
    std::atomic<std::size_t> m_bytes_downloaded{0};
    std::atomic<std::size_t> m_requests_timed_out{0};
    std::atomic<std::size_t> m_requests_errored{0};
    std::atomic<std::size_t> m_connections_reset{0};
    std::atomic<bool> m_interrupt_set{false};
    std::chrono::system_clock::time_point m_last_update_time{
        std::chrono::system_clock::now()};
    std::size_t m_last_reported_passwords_checked{0};
    std::size_t m_last_reported_bytes_downloaded{0};
};

