package registry

import (
	"testing"
)

func TestIdentify_ByIncludePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"boost/algorithm/string.hpp", "boost"},
		{"openssl/ssl.h", "openssl"},
		{"zlib.h", "zlib"},
		{"nlohmann/json.hpp", "nlohmann-json"},
		{"absl/strings/str_format.h", "abseil"},
		{"fmt/core.h", "fmt"},
		{"spdlog/spdlog.h", "spdlog"},
	}
	for _, tt := range tests {
		got := Identify(tt.input)
		if got == nil {
			t.Errorf("Identify(%q) = nil, want %q", tt.input, tt.want)
			continue
		}
		if got.Name != tt.want {
			t.Errorf("Identify(%q).Name = %q, want %q", tt.input, got.Name, tt.want)
		}
	}
}

func TestIdentify_Unknown(t *testing.T) {
	if got := Identify("unknown/lib/header.h"); got != nil {
		t.Errorf("Identify(unknown) = %v, want nil", got)
	}
}

func TestIdentify_NoFalsePositiveOnSubstring(t *testing.T) {
	falseInputs := []string{
		"reformatter",
		"resultvalue",
		"missile",
		"eventbridge",
		"formula",
	}
	for _, input := range falseInputs {
		if got := Identify(input); got != nil {
			t.Errorf("Identify(%q) = %q, want nil (false positive)", input, got.Name)
		}
	}
}

func TestIdentify_WordBoundaryStillMatches(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"lib/fmt/core.h", "fmt"},
		{"/opt/openssl/lib/libssl.so", "openssl"},
		{"libuv-1.44", "libuv"},
		{"third_party/zlib/zlib.h", "zlib"},
	}
	for _, tt := range tests {
		got := Identify(tt.input)
		if got == nil {
			t.Errorf("Identify(%q) = nil, want %q", tt.input, tt.want)
			continue
		}
		if got.Name != tt.want {
			t.Errorf("Identify(%q).Name = %q, want %q", tt.input, got.Name, tt.want)
		}
	}
}

func TestIsSystemHeader_Stdlib(t *testing.T) {
	stdlib := []string{"vector", "iostream", "string", "algorithm", "memory", "cstdint"}
	for _, h := range stdlib {
		if !IsSystemHeader(h) {
			t.Errorf("IsSystemHeader(%q) = false, want true", h)
		}
	}
}

func TestIsSystemHeader_ThirdParty(t *testing.T) {
	third := []string{"boost/algorithm.hpp", "openssl/ssl.h", "nlohmann/json.hpp"}
	for _, h := range third {
		if IsSystemHeader(h) {
			t.Errorf("IsSystemHeader(%q) = true, want false", h)
		}
	}
}
