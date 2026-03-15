#pragma once
#include <string>

// Project-internal header.
// The header scanner must NOT report this as a third-party dependency.

struct AppConfig {
    std::string host;
    int port;
    bool tls;
};

AppConfig loadConfig(const std::string& path);
