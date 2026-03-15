#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <cstdint>

// Third-party includes
#include <boost/asio.hpp>
#include <openssl/ssl.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

// Project-internal include — must NOT be reported as a third-party dependency
#include "internal_utils.h"

int main() {
    nlohmann::json j = {{"key", "value"}};
    spdlog::info("Hello from cpp-sbom-builder sample");
    return 0;
}
