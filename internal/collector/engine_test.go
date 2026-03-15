package collector

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/probers"
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

func emptyConanGraph() *probers.ConanScanResult {
	return &probers.ConanScanResult{
		DirectNames: make(map[string]bool),
		Edges:       make(map[string][]string),
	}
}

func TestFoldOutputs_DeterministicRegardlessOfOrder(t *testing.T) {
	engine := &Engine{Verbose: false}

	conanOut := func() detectorOutput {
		return detectorOutput{
			name: "conan",
			components: []*inventory.Component{{
				Name:            "openssl",
				Version:         "3.1.0",
				PURL:            "pkg:conan/openssl@3.1.0",
				DetectionSource: "conan",
				Description:     "TLS library",
			}},
		}
	}
	headerOut := func() detectorOutput {
		return detectorOutput{
			name: "header-scan",
			components: []*inventory.Component{{
				Name:            "openssl",
				Version:         "unknown",
				DetectionSource: "header-scan",
				IncludePaths:    []string{"/usr/include/openssl"},
			}},
		}
	}

	r1 := runResult{outputs: []detectorOutput{conanOut(), headerOut()}, conanGraph: emptyConanGraph()}
	r2 := runResult{outputs: []detectorOutput{headerOut(), conanOut()}, conanGraph: emptyConanGraph()}

	comps1, fired1, _ := engine.foldOutputs(r1)
	comps2, fired2, _ := engine.foldOutputs(r2)

	c1 := findComponent(comps1, "openssl")
	c2 := findComponent(comps2, "openssl")

	if c1 == nil || c2 == nil {
		t.Fatal("expected openssl in both results")
	}
	if c1.Version != c2.Version {
		t.Errorf("version mismatch: %q vs %q", c1.Version, c2.Version)
	}
	if c1.DetectionSource != c2.DetectionSource {
		t.Errorf("source mismatch: %q vs %q", c1.DetectionSource, c2.DetectionSource)
	}
	if c1.Description != c2.Description {
		t.Errorf("description mismatch: %q vs %q", c1.Description, c2.Description)
	}
	if len(fired1) != len(fired2) {
		t.Fatalf("fired length mismatch: %d vs %d", len(fired1), len(fired2))
	}
	for i := range fired1 {
		if fired1[i] != fired2[i] {
			t.Errorf("fired[%d] mismatch: %q vs %q", i, fired1[i], fired2[i])
		}
	}
}

func TestFoldOutputs_HigherTrustDataPreferred(t *testing.T) {
	engine := &Engine{Verbose: false}

	// Lower-trust detector arrives first, but higher-trust data should win.
	r := runResult{
		outputs: []detectorOutput{
			{
				name: "header-scan",
				components: []*inventory.Component{{
					Name:            "zlib",
					Version:         "unknown",
					DetectionSource: "header-scan",
					Description:     "compression",
					IncludePaths:    []string{"/usr/include/zlib.h"},
				}},
			},
			{
				name: "conan",
				components: []*inventory.Component{{
					Name:            "zlib",
					Version:         "1.3.1",
					PURL:            "pkg:conan/zlib@1.3.1",
					DetectionSource: "conan",
					Description:     "A massively spiffy yet delicately unobtrusive compression library",
				}},
			},
		},
		conanGraph: emptyConanGraph(),
	}

	comps, _, _ := engine.foldOutputs(r)
	c := findComponent(comps, "zlib")
	if c == nil {
		t.Fatal("expected zlib component")
	}
	if c.Version != "1.3.1" {
		t.Errorf("expected version 1.3.1 from conan, got %q", c.Version)
	}
	if c.DetectionSource != "conan" {
		t.Errorf("expected conan source, got %q", c.DetectionSource)
	}
	if c.Description != "A massively spiffy yet delicately unobtrusive compression library" {
		t.Errorf("expected conan description, got %q", c.Description)
	}
	if len(c.IncludePaths) != 1 || c.IncludePaths[0] != "/usr/include/zlib.h" {
		t.Errorf("expected header-scan include paths to be accumulated, got %v", c.IncludePaths)
	}
}

func TestFoldOutputs_ErroredDetectorSkipped(t *testing.T) {
	engine := &Engine{Verbose: false}

	r := runResult{
		outputs: []detectorOutput{
			{name: "conan", components: []*inventory.Component{{
				Name: "boost", Version: "1.84.0", DetectionSource: "conan",
			}}},
			{name: "vcpkg", err: fmt.Errorf("vcpkg not found")},
		},
		conanGraph: emptyConanGraph(),
	}

	comps, fired, quiet := engine.foldOutputs(r)

	if findComponent(comps, "boost") == nil {
		t.Error("expected boost component")
	}
	if len(fired) != 1 || fired[0] != "conan" {
		t.Errorf("expected fired=[conan], got %v", fired)
	}
	if len(quiet) != 1 || quiet[0] != "vcpkg" {
		t.Errorf("expected quiet=[vcpkg], got %v", quiet)
	}
}

func findComponent(comps []*inventory.Component, name string) *inventory.Component {
	key := inventory.NormalizeKey(name)
	for _, c := range comps {
		if inventory.NormalizeKey(c.Name) == key {
			return c
		}
	}
	return nil
}

func TestSortedComponents_DeterministicOrder(t *testing.T) {
	merged := map[string]*inventory.Component{
		"zlib":    {Name: "zlib"},
		"boost":   {Name: "boost"},
		"openssl": {Name: "openssl"},
	}

	for i := 0; i < 50; i++ {
		out := sortedComponents(merged)
		if len(out) != 3 {
			t.Fatalf("expected 3 components, got %d", len(out))
		}
		if out[0].Name != "boost" || out[1].Name != "openssl" || out[2].Name != "zlib" {
			t.Fatalf("unexpected order: %s, %s, %s", out[0].Name, out[1].Name, out[2].Name)
		}
	}
}
