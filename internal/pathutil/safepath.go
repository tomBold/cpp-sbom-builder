package pathutil

import (
	"path/filepath"
	"strings"
)

// IsUnderRoot returns true if path (after Clean and Abs) is under root.
// Returns false for "/", "", ".", or any path that escapes root.
func IsUnderRoot(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	clean := filepath.Clean(path)
	abs, err := filepath.Abs(clean)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	if abs == "/" || abs == "." || absRoot == "/" || absRoot == "" {
		return false
	}
	rel, err := filepath.Rel(absRoot, abs)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..") && rel != ".."
}

// RejectPath returns true if path should never be used for file operations
// (e.g. "/", "", ".", or paths that could walk the whole filesystem).
func RejectPath(path string) bool {
	if path == "" {
		return true
	}
	clean := filepath.Clean(path)
	return clean == "." || clean == ".." || clean == "/" || clean == string(filepath.Separator)
}
