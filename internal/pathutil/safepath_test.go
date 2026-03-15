package pathutil

import (
	"path/filepath"
	"testing"
)

func TestIsUnderRoot(t *testing.T) {
	root := t.TempDir()
	absRoot, _ := filepath.Abs(root)
	child := filepath.Join(root, "src")
	deep := filepath.Join(root, "src", "foo")

	tests := []struct {
		path string
		r    string
		want bool
	}{
		{child, absRoot, true},
		{deep, absRoot, true},
		{root, absRoot, true},
		{"", absRoot, false},
		{absRoot, "", false},
		{root + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(root), absRoot, true},
	}

	for _, tt := range tests {
		got := IsUnderRoot(tt.path, tt.r)
		if got != tt.want {
			t.Errorf("IsUnderRoot(%q, %q) = %v, want %v", tt.path, tt.r, got, tt.want)
		}
	}
}

func TestRejectPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"", true},
		{"/", true},
		{".", true},
		{"..", true},
		{"/home/project", false},
		{"src/foo", false},
	}

	for _, tt := range tests {
		got := RejectPath(tt.path)
		if got != tt.want {
			t.Errorf("RejectPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
