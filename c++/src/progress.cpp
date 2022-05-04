#include <fmt/core.h>

#include "progress.hpp"

Progress::Progress(std::size_t total_passwords)
    : m_total_passwords(total_passwords),
      m_progress_bar(
          indicators::option::BarWidth{100}, indicators::option::Start{"["},
          indicators::option::Fill{"■"}, indicators::option::Lead{"■"},
          indicators::option::Remainder{"-"}, indicators::option::End{" ]"},
          indicators::option::MaxProgress(total_passwords),
          indicators::option::ShowElapsedTime{true},
          indicators::option::ShowRemainingTime{true},
          indicators::option::PostfixText{fmt::format("0/{}", total_passwords)},
          indicators::option::ForegroundColor{indicators::Color::cyan},
          indicators::option::FontStyles{
              std::vector<indicators::FontStyle>{indicators::FontStyle::bold}})
{
    indicators::show_console_cursor(false);
}

Progress::~Progress() { indicators::show_console_cursor(true); }

bool Progress::update_progress_bar()
{
    auto update_time = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        update_time - m_last_update_time)
                        .count() /
                    1000.f;
    m_last_update_time = update_time;

    auto bytes_downloaded = m_bytes_downloaded.load();
    auto mb_per_sec = (bytes_downloaded - m_last_reported_bytes_downloaded) /
                      duration / 1024 / 1024;
    m_last_reported_bytes_downloaded = bytes_downloaded;

    auto passwords_checked = m_passwords_checked.load();
    auto requests_processed =
        passwords_checked - m_last_reported_passwords_checked;
    auto req_per_sec = requests_processed / duration;
    m_last_reported_passwords_checked = passwords_checked;

    if (requests_processed == 0)
    {
        return false;
    }

    auto postfix = fmt::format(
        "{:6.2f} MB/s, {:8.2f} req/s, E:{}/T:{}/R:{} - {}/{}", mb_per_sec,
        req_per_sec, m_requests_errored.load(), m_requests_timed_out.load(),
        m_connections_reset.load(), passwords_checked, m_total_passwords);
    m_progress_bar.set_option(indicators::option::PostfixText{postfix});
    m_progress_bar.set_progress(passwords_checked);
    return m_progress_bar.is_completed();
}
