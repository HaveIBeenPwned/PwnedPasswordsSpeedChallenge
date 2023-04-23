#pragma once

#include <string>
#include <vector>

struct Password
{
    std::string value;
    std::size_t count{0};
    bool checked{false};
};

std::vector<Password> read_passwords(const std::string &filename);
void write_results(const std::vector<Password> &passwords,
                   const std::string &output_filename);
