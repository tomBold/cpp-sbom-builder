package testutil

import (
	"path/filepath"
	"runtime"
)

// ProjectRoot returns the repository root derived from the caller's
// source file location (which must be two directories below the root,
// e.g. internal/xxx/).
func ProjectRoot() string {
	_, file, _, _ := runtime.Caller(1)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// DemoDir returns the path to the demo/ synthetic project.
func DemoDir() string {
	_, file, _, _ := runtime.Caller(1)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "demo")
}

// TestdataDir returns the path to testdata/fixtures/.
func TestdataDir() string {
	_, file, _, _ := runtime.Caller(1)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "testdata", "fixtures")
}
