#include <fstream>
#include <string>
#include <vector>

#include <fmt/os.h>

#include "password.hpp"
#include "timer.hpp"

static inline bool not_space(char c) { return !std::isspace(c); }

static void trim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
}

std::vector<Password> read_passwords(const std::string &filename)
{
    Timer t;
    std::ifstream password_file(filename);
    std::vector<Password> passwords;
    for (std::string password; std::getline(password_file, password);)
    {
        trim(password);
        passwords.emplace_back(password, 0, false);
        password.clear();
    }
    fmt::print("Read {} passwords in {}\n", passwords.size(), t.get_fmt());
    return passwords;
}

void write_results(const std::vector<Password> &passwords,
                   const std::string &output_filename)
{
    fmt::print("Writing results to {}\n", output_filename);
    Timer t;
    {
        auto out = fmt::output_file(
            output_filename, fmt::file::WRONLY | fmt::file::CREATE | O_TRUNC);
        for (const auto &password : passwords)
        {
            out.print("{}, {}\n", password.value, password.count);
        }
    }
    fmt::print("Results written to {} in {}\n", output_filename, t.get_fmt());
}

