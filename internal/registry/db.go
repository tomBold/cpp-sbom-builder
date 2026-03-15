package registry

import "strings"

type KnownLib struct {
	Name        string
	PathHints   []string
	IncludePats []string
	PURLPrefix  string
	Description string
}

var Catalog = []KnownLib{
	{
		Name:        "boost",
		PathHints:   []string{"boost"},
		IncludePats: []string{"boost/"},
		PURLPrefix:  "pkg:conan/boost",
		Description: "Boost C++ Libraries",
	},
	{
		Name:        "openssl",
		PathHints:   []string{"openssl", "ssl", "crypto"},
		IncludePats: []string{"openssl/", "ssl.h", "crypto.h"},
		PURLPrefix:  "pkg:conan/openssl",
		Description: "OpenSSL cryptography library",
	},
	{
		Name:        "zlib",
		PathHints:   []string{"zlib"},
		IncludePats: []string{"zlib.h"},
		PURLPrefix:  "pkg:conan/zlib",
		Description: "zlib compression library",
	},
	{
		Name:        "libcurl",
		PathHints:   []string{"curl", "libcurl"},
		IncludePats: []string{"curl/curl.h", "curl/"},
		PURLPrefix:  "pkg:conan/libcurl",
		Description: "libcurl — the multiprotocol file transfer library",
	},
	{
		Name:        "sqlite3",
		PathHints:   []string{"sqlite", "sqlite3"},
		IncludePats: []string{"sqlite3.h"},
		PURLPrefix:  "pkg:conan/sqlite3",
		Description: "SQLite embedded database",
	},
	{
		Name:        "googletest",
		PathHints:   []string{"gtest", "googletest", "googlemock"},
		IncludePats: []string{"gtest/gtest.h", "gmock/gmock.h"},
		PURLPrefix:  "pkg:github/google/googletest",
		Description: "Google Test C++ testing framework",
	},
	{
		Name:        "nlohmann-json",
		PathHints:   []string{"nlohmann"},
		IncludePats: []string{"nlohmann/json.hpp", "nlohmann/"},
		PURLPrefix:  "pkg:github/nlohmann/json",
		Description: "JSON for Modern C++",
	},
	{
		Name:        "eigen",
		PathHints:   []string{"eigen", "Eigen"},
		IncludePats: []string{"Eigen/", "eigen3/"},
		PURLPrefix:  "pkg:conan/eigen",
		Description: "Eigen linear algebra library",
	},
	{
		Name:        "protobuf",
		PathHints:   []string{"protobuf", "google/protobuf"},
		IncludePats: []string{"google/protobuf/", "protobuf/"},
		PURLPrefix:  "pkg:conan/protobuf",
		Description: "Google Protocol Buffers",
	},
	{
		Name:        "grpc",
		PathHints:   []string{"grpc", "grpcpp"},
		IncludePats: []string{"grpc/grpc.h", "grpcpp/"},
		PURLPrefix:  "pkg:conan/grpc",
		Description: "gRPC remote procedure call framework",
	},
	{
		Name:        "abseil",
		PathHints:   []string{"absl", "abseil"},
		IncludePats: []string{"absl/"},
		PURLPrefix:  "pkg:conan/abseil",
		Description: "Abseil C++ Common Libraries",
	},
	{
		Name:        "fmt",
		PathHints:   []string{"fmt"},
		IncludePats: []string{"fmt/format.h", "fmt/core.h", "fmt/"},
		PURLPrefix:  "pkg:conan/fmt",
		Description: "{fmt} formatting library",
	},
	{
		Name:        "spdlog",
		PathHints:   []string{"spdlog"},
		IncludePats: []string{"spdlog/spdlog.h", "spdlog/"},
		PURLPrefix:  "pkg:conan/spdlog",
		Description: "Fast C++ logging library",
	},
	{
		Name:        "catch2",
		PathHints:   []string{"catch2", "Catch2"},
		IncludePats: []string{"catch2/catch.hpp", "catch2/catch_all.hpp"},
		PURLPrefix:  "pkg:conan/catch2",
		Description: "Catch2 C++ test framework",
	},
	{
		Name:        "libuv",
		PathHints:   []string{"libuv", "uv"},
		IncludePats: []string{"uv.h", "uv/"},
		PURLPrefix:  "pkg:conan/libuv",
		Description: "libuv asynchronous I/O library",
	},
	{
		Name:        "libpng",
		PathHints:   []string{"libpng", "png"},
		IncludePats: []string{"png.h", "libpng/"},
		PURLPrefix:  "pkg:conan/libpng",
		Description: "libpng PNG image library",
	},
	{
		Name:        "libjpeg",
		PathHints:   []string{"libjpeg", "jpeg"},
		IncludePats: []string{"jpeglib.h", "jerror.h"},
		PURLPrefix:  "pkg:conan/libjpeg",
		Description: "libjpeg JPEG image library",
	},
	{
		Name:        "opencv",
		PathHints:   []string{"opencv", "opencv2"},
		IncludePats: []string{"opencv2/", "opencv/"},
		PURLPrefix:  "pkg:conan/opencv",
		Description: "OpenCV computer vision library",
	},
	{
		Name:        "poco",
		PathHints:   []string{"Poco", "poco"},
		IncludePats: []string{"Poco/"},
		PURLPrefix:  "pkg:conan/poco",
		Description: "POCO C++ Libraries",
	},
	{
		Name:        "qt",
		PathHints:   []string{"Qt5", "Qt6", "QtCore", "QtWidgets"},
		IncludePats: []string{"QtCore/", "QtWidgets/", "QtGui/", "QObject"},
		PURLPrefix:  "pkg:conan/qt",
		Description: "Qt application framework",
	},
	{
		Name:        "tbb",
		PathHints:   []string{"tbb", "oneapi/tbb"},
		IncludePats: []string{"tbb/tbb.h", "tbb/", "oneapi/tbb/"},
		PURLPrefix:  "pkg:conan/onetbb",
		Description: "Intel Threading Building Blocks",
	},
	{
		Name:        "glfw",
		PathHints:   []string{"glfw", "GLFW"},
		IncludePats: []string{"GLFW/glfw3.h"},
		PURLPrefix:  "pkg:conan/glfw",
		Description: "GLFW OpenGL windowing library",
	},
	{
		Name:        "glm",
		PathHints:   []string{"glm"},
		IncludePats: []string{"glm/glm.hpp", "glm/"},
		PURLPrefix:  "pkg:conan/glm",
		Description: "OpenGL Mathematics library",
	},
	{
		Name:        "rapidjson",
		PathHints:   []string{"rapidjson"},
		IncludePats: []string{"rapidjson/document.h", "rapidjson/"},
		PURLPrefix:  "pkg:conan/rapidjson",
		Description: "RapidJSON fast JSON parser/generator",
	},
	{
		Name:        "yaml-cpp",
		PathHints:   []string{"yaml-cpp", "yaml_cpp"},
		IncludePats: []string{"yaml-cpp/yaml.h"},
		PURLPrefix:  "pkg:conan/yaml-cpp",
		Description: "yaml-cpp YAML parser",
	},
	{
		Name:        "pugixml",
		PathHints:   []string{"pugixml"},
		IncludePats: []string{"pugixml.hpp"},
		PURLPrefix:  "pkg:conan/pugixml",
		Description: "pugixml XML parser",
	},
	{
		Name:        "zstd",
		PathHints:   []string{"zstd"},
		IncludePats: []string{"zstd.h"},
		PURLPrefix:  "pkg:conan/zstd",
		Description: "Zstandard compression library",
	},
	{
		Name:        "lz4",
		PathHints:   []string{"lz4"},
		IncludePats: []string{"lz4.h", "lz4frame.h"},
		PURLPrefix:  "pkg:conan/lz4",
		Description: "LZ4 compression library",
	},
	{
		Name:        "flatbuffers",
		PathHints:   []string{"flatbuffers"},
		IncludePats: []string{"flatbuffers/flatbuffers.h", "flatbuffers/"},
		PURLPrefix:  "pkg:conan/flatbuffers",
		Description: "FlatBuffers serialization library",
	},
	{
		Name:        "asio",
		PathHints:   []string{"asio"},
		IncludePats: []string{"asio.hpp", "asio/"},
		PURLPrefix:  "pkg:conan/asio",
		Description: "Asio C++ asynchronous networking library",
	},
	{
		Name:        "websocketpp",
		PathHints:   []string{"websocketpp"},
		IncludePats: []string{"websocketpp/"},
		PURLPrefix:  "pkg:conan/websocketpp",
		Description: "WebSocket++ library",
	},
	{
		Name:        "benchmark",
		PathHints:   []string{"benchmark"},
		IncludePats: []string{"benchmark/benchmark.h"},
		PURLPrefix:  "pkg:github/google/benchmark",
		Description: "Google Benchmark microbenchmark library",
	},
	{
		Name:        "cereal",
		PathHints:   []string{"cereal"},
		IncludePats: []string{"cereal/cereal.hpp", "cereal/"},
		PURLPrefix:  "pkg:conan/cereal",
		Description: "cereal C++ serialization library",
	},
	{
		Name:        "cxxopts",
		PathHints:   []string{"cxxopts"},
		IncludePats: []string{"cxxopts.hpp"},
		PURLPrefix:  "pkg:conan/cxxopts",
		Description: "cxxopts command-line option parser",
	},
	{
		Name:        "cli11",
		PathHints:   []string{"CLI11", "CLI"},
		IncludePats: []string{"CLI/CLI.hpp"},
		PURLPrefix:  "pkg:conan/cli11",
		Description: "CLI11 command-line parser",
	},
	{
		Name:        "re2",
		PathHints:   []string{"re2"},
		IncludePats: []string{"re2/re2.h"},
		PURLPrefix:  "pkg:conan/re2",
		Description: "RE2 regular expression library",
	},
	{
		Name:        "leveldb",
		PathHints:   []string{"leveldb"},
		IncludePats: []string{"leveldb/db.h", "leveldb/"},
		PURLPrefix:  "pkg:conan/leveldb",
		Description: "LevelDB key-value storage",
	},
	{
		Name:        "rocksdb",
		PathHints:   []string{"rocksdb"},
		IncludePats: []string{"rocksdb/db.h", "rocksdb/"},
		PURLPrefix:  "pkg:conan/rocksdb",
		Description: "RocksDB embedded database",
	},
	{
		Name:        "libsodium",
		PathHints:   []string{"sodium", "libsodium"},
		IncludePats: []string{"sodium.h", "sodium/"},
		PURLPrefix:  "pkg:conan/libsodium",
		Description: "libsodium cryptography library",
	},
	{
		Name:        "mbedtls",
		PathHints:   []string{"mbedtls"},
		IncludePats: []string{"mbedtls/ssl.h", "mbedtls/"},
		PURLPrefix:  "pkg:conan/mbedtls",
		Description: "Mbed TLS cryptography library",
	},
	{
		Name:        "libevent",
		PathHints:   []string{"libevent", "event"},
		IncludePats: []string{"event2/event.h"},
		PURLPrefix:  "pkg:conan/libevent",
		Description: "libevent event notification library",
	},
	{
		Name:        "arrow",
		PathHints:   []string{"arrow"},
		IncludePats: []string{"arrow/api.h", "arrow/"},
		PURLPrefix:  "pkg:conan/arrow",
		Description: "Apache Arrow columnar data format",
	},
	{
		Name:        "msgpack",
		PathHints:   []string{"msgpack"},
		IncludePats: []string{"msgpack.hpp", "msgpack/"},
		PURLPrefix:  "pkg:conan/msgpack-cxx",
		Description: "MessagePack serialization library",
	},
	{
		Name:        "folly",
		PathHints:   []string{"folly"},
		IncludePats: []string{"folly/"},
		PURLPrefix:  "pkg:conan/folly",
		Description: "Facebook Open-source Library",
	},
	{
		Name:        "libgcc",
		PathHints:   []string{"libgcc"},
		IncludePats: []string{},
		PURLPrefix:  "pkg:generic/libgcc",
		Description: "GCC low-level runtime library",
	},
	{
		Name:        "newlib",
		PathHints:   []string{"newlib", "libc_nano", "libnosys"},
		IncludePats: []string{},
		PURLPrefix:  "pkg:generic/newlib",
		Description: "Newlib C standard library for embedded systems",
	},
}

var systemHeaders = buildSystemHeaderSet()

func buildSystemHeaderSet() map[string]struct{} {
	raw := []string{
		"assert.h", "complex.h", "ctype.h", "errno.h", "fenv.h", "float.h",
		"inttypes.h", "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h",
		"signal.h", "stdalign.h", "stdarg.h", "stdatomic.h", "stdbool.h",
		"stddef.h", "stdint.h", "stdio.h", "stdlib.h", "stdnoreturn.h",
		"string.h", "tgmath.h", "threads.h", "time.h", "uchar.h", "wchar.h", "wctype.h",
		"unistd.h", "fcntl.h", "sys/types.h", "sys/stat.h", "sys/socket.h",
		"sys/wait.h", "sys/mman.h", "sys/time.h", "sys/ioctl.h", "sys/select.h",
		"netinet/in.h", "arpa/inet.h", "netdb.h", "pthread.h", "semaphore.h",
		"dirent.h", "dlfcn.h", "poll.h", "termios.h",
		"windows.h", "winsock2.h", "ws2tcpip.h", "winbase.h", "windef.h",
		"winnt.h", "shellapi.h", "shlobj.h", "commctrl.h",
		"algorithm", "any", "array", "atomic", "barrier", "bit", "bitset",
		"cassert", "cctype", "cerrno", "cfenv", "cfloat", "charconv", "chrono",
		"cinttypes", "climits", "clocale", "cmath", "codecvt", "compare",
		"complex", "concepts", "condition_variable", "coroutine", "csetjmp",
		"csignal", "cstdarg", "cstddef", "cstdint", "cstdio", "cstdlib",
		"cstring", "ctime", "cuchar", "cwchar", "cwctype", "deque", "exception",
		"execution", "expected", "filesystem", "format", "forward_list", "fstream",
		"functional", "future", "generator", "initializer_list", "iomanip",
		"ios", "iosfwd", "iostream", "istream", "iterator", "latch", "limits",
		"list", "locale", "map", "memory", "memory_resource", "mutex", "new",
		"numbers", "numeric", "optional", "ostream", "print", "queue", "random",
		"ranges", "ratio", "regex", "scoped_allocator", "semaphore", "set",
		"shared_mutex", "source_location", "span", "sstream", "stack",
		"stdexcept", "stop_token", "streambuf", "string", "string_view",
		"syncstream", "system_error", "thread", "tuple", "type_traits",
		"typeindex", "typeinfo", "unordered_map", "unordered_set", "utility",
		"valarray", "variant", "vector", "version",
	}
	m := make(map[string]struct{}, len(raw))
	for _, h := range raw {
		m[h] = struct{}{}
	}
	return m
}

func IsSystemHeader(include string) bool {
	_, ok := systemHeaders[strings.TrimSpace(include)]
	return ok
}

func Identify(s string) *KnownLib {
	lower := strings.ToLower(s)
	for i := range Catalog {
		entry := &Catalog[i]
		for _, hint := range entry.PathHints {
			if strings.Contains(lower, strings.ToLower(hint)) {
				return entry
			}
		}
		for _, pat := range entry.IncludePats {
			if strings.Contains(lower, strings.ToLower(pat)) {
				return entry
			}
		}
	}
	return nil
}
