package testutil

import (
	"path/filepath"
	"runtime"
)

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
