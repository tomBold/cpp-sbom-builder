package collector

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
)

func demoDir() string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "demo")
}

func TestEngine_Scan_ReturnsComponents(t *testing.T) {
	e := New(demoDir(), false)
	result, err := e.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Components) == 0 {
		t.Error("expected at least one component")
	}
	if result.DependencyTree == nil {
		t.Error("expected non-nil DependencyTree")
	}
}

func TestEngine_Scan_StrategiesUsed(t *testing.T) {
	e := New(demoDir(), false)
	result, err := e.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.StrategiesUsed) == 0 {
		t.Error("expected at least one strategy to find results")
	}
}

func TestEngine_Scan_DeduplicatesByName(t *testing.T) {
	e := New(demoDir(), false)
	result, err := e.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	seen := make(map[string]bool)
	for _, c := range result.Components {
		key := inventory.NormalizeKey(c.Name)
		if seen[key] {
			t.Errorf("duplicate component: %s", c.Name)
		}
		seen[key] = true
	}
}
