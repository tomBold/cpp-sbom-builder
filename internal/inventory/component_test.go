package inventory

import (
	"testing"
)

func TestComponent_Key(t *testing.T) {
	c := &Component{Name: "boost", Version: "1.82.0"}
	if got := c.Key(); got != "boost@1.82.0" {
		t.Errorf("Key() = %q, want boost@1.82.0", got)
	}
}

func TestComponent_DependencyType(t *testing.T) {
	if got := (&Component{IsDirect: true}).DependencyType(); got != "direct" {
		t.Errorf("DependencyType(direct) = %q, want direct", got)
	}
	if got := (&Component{IsDirect: false}).DependencyType(); got != "transitive" {
		t.Errorf("DependencyType(transitive) = %q, want transitive", got)
	}
}

func TestComponent_BOMRef_UsesPURL(t *testing.T) {
	c := &Component{Name: "boost", Version: "1.82.0", PURL: "pkg:conan/boost@1.82.0"}
	if got := c.BOMRef(); got != "pkg:conan/boost@1.82.0" {
		t.Errorf("BOMRef() = %q, want pkg:conan/boost@1.82.0", got)
	}
}

func TestComponent_BOMRef_FallbackToGeneric(t *testing.T) {
	c := &Component{Name: "mylib", Version: "1.0", PURL: ""}
	if got := c.BOMRef(); got != "pkg:generic/mylib@1.0" {
		t.Errorf("BOMRef() = %q, want pkg:generic/mylib@1.0", got)
	}
}

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
