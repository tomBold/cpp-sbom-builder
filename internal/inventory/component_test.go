package inventory

import (
	"testing"
)

func TestNormalizeKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Boost", "boost"},
		{"nlohmann_json", "nlohmann-json"},
		{"foo.bar", "foo-bar"},
	}
	for _, tt := range tests {
		if got := NormalizeKey(tt.input); got != tt.want {
			t.Errorf("NormalizeKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
