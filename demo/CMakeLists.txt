cmake_minimum_required(VERSION 3.20)
project(SampleApp VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Direct manifest-style declarations ──────────────────────────────────────
# These are detected by the CMake strategy.

# find_package — detected at confidence 0.85
find_package(OpenSSL REQUIRED)
find_package(Boost 1.82 REQUIRED COMPONENTS filesystem system)

# FetchContent — detected at confidence 0.80, GIT_TAG becomes version
include(FetchContent)
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        10.2.1
)
FetchContent_MakeAvailable(fmt)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.13.0
)
FetchContent_MakeAvailable(spdlog)

# ── Target declarations ──────────────────────────────────────────────────────
add_executable(sample_app
    src/main.cpp
    src/http_client.cpp
)

target_include_directories(sample_app PRIVATE include)

# target_link_libraries with Foo::Bar namespace tokens — detected at 0.70
target_link_libraries(sample_app
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::filesystem
        fmt::fmt
        spdlog::spdlog
)
