#include <iostream>
#include <string>
#include <vector>
#include <memory>

// ── Third-party includes (detected by header-scan strategy) ──────────────────

// Detected: nlohmann-json
#include <nlohmann/json.hpp>

// Detected: spdlog
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

// Detected: boost
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

// Detected: openssl
#include <openssl/ssl.h>
#include <openssl/err.h>

// ── Project-internal include (must NOT be detected as third-party) ────────────
#include "app.hpp"

// Forward declaration from http_client
void fetchURL(const std::string& url);

int main(int argc, char* argv[]) {
    auto logger = spdlog::stdout_color_mt("console");
    logger->info("cpp-sbom-builder sample application");

    // Parse a JSON config
    nlohmann::json config = {
        {"host", "localhost"},
        {"port", 8080},
        {"tls", true}
    };

    std::string host = config["host"];
    logger->info("Connecting to {}:{}", host, config["port"].get<int>());

    // Use Boost.Filesystem
    boost::filesystem::path projectRoot = ".";
    logger->info("Project root: {}", projectRoot.string());

    // OpenSSL init
    SSL_library_init();
    SSL_load_error_strings();

    fetchURL("https://example.com/api");

    return 0;
}
