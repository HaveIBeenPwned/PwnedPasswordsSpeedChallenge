cmake_minimum_required(VERSION 3.16)
project(PwnedPasswordsSpeedChallenge VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system coroutine program_options)
find_package(OpenSSL REQUIRED)

add_subdirectory(src)
