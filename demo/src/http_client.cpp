#include <string>
#include <iostream>

// Detected: grpc
#include <grpc/grpc.h>
#include <grpcpp/channel.h>

// Detected: abseil
#include <absl/strings/str_format.h>

// Detected: yaml-cpp
#include <yaml-cpp/yaml.h>

// Detected: zlib
#include <zlib.h>

// Detected: libcurl
#include <curl/curl.h>

// Detected: pugixml (header-only, no manifest entry — tests confidence filtering)
#include <pugixml.hpp>

void fetchURL(const std::string& url) {
    // Initialise gRPC channel
    grpc_init();

    // Load YAML config
    YAML::Node config = YAML::Load("host: localhost\nport: 8080");
    std::string host = config["host"].as<std::string>();

    // Use abseil string formatting
    std::string msg = absl::StrFormat("Fetching %s from %s", url, host);
    std::cout << msg << "\n";

    // Use curl for HTTP
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    // Use zlib for compression
    z_stream zst{};
    deflateInit(&zst, Z_DEFAULT_COMPRESSION);
    deflateEnd(&zst);

    grpc_shutdown();
}
