cmake_minimum_required(VERSION 3.20)
project(TestApp VERSION 1.0.0)

find_package(OpenSSL REQUIRED)
find_package(Boost 1.82 REQUIRED COMPONENTS filesystem system)

include(FetchContent)
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        10.1.1
)
FetchContent_MakeAvailable(fmt)

add_executable(test_app main.cpp)
target_link_libraries(test_app PRIVATE OpenSSL::SSL Boost::filesystem fmt::fmt)
