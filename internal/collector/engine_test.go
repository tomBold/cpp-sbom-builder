package collector

import (
	"fmt"
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
	e := New(demoDir(), false, DefaultDetectors())
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
	e := New(demoDir(), false, DefaultDetectors())
	result, err := e.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.StrategiesUsed) == 0 {
		t.Error("expected at least one strategy to find results")
	}
}

func TestEngine_Scan_DeduplicatesByName(t *testing.T) {
	e := New(demoDir(), false, DefaultDetectors())
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

	noGraph := func() (map[string]bool, map[string][]string) {
		return make(map[string]bool), make(map[string][]string)
	}
	d1, e1 := noGraph()
	r1 := runResult{outputs: []detectorOutput{conanOut(), headerOut()}, directNames: d1, edges: e1}
	d2, e2 := noGraph()
	r2 := runResult{outputs: []detectorOutput{headerOut(), conanOut()}, directNames: d2, edges: e2}

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
		directNames: make(map[string]bool),
		edges:       make(map[string][]string),
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
		directNames: make(map[string]bool),
		edges:       make(map[string][]string),
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

// --- dependency-injection tests ---

type fakeDetector struct {
	name       string
	components []*inventory.Component
	err        error
}

func (f *fakeDetector) Name() string { return f.name }
func (f *fakeDetector) Scan(projectRoot string, verbose bool) ([]*inventory.Component, error) {
	return f.components, f.err
}

type fakeGraphDetector struct {
	fakeDetector
	directNames map[string]bool
	edges       map[string][]string
}

func (f *fakeGraphDetector) ScanGraph(projectRoot string, verbose bool) ([]*inventory.Component, map[string]bool, map[string][]string) {
	return f.components, f.directNames, f.edges
}

func TestEngine_WithInjectedDetectors(t *testing.T) {
	e := New(".", false, []Detector{
		&fakeDetector{
			name: "fake",
			components: []*inventory.Component{
				{Name: "testlib", Version: "1.0.0", DetectionSource: "fake"},
			},
		},
	})

	result, err := e.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(result.Components))
	}
	if result.Components[0].Name != "testlib" {
		t.Errorf("expected testlib, got %s", result.Components[0].Name)
	}
	if len(result.StrategiesUsed) != 1 || result.StrategiesUsed[0] != "fake" {
		t.Errorf("expected strategies=[fake], got %v", result.StrategiesUsed)
	}
}

func TestEngine_WithGraphDetector(t *testing.T) {
	e := New(".", false, []Detector{
		&fakeGraphDetector{
			fakeDetector: fakeDetector{
				name: "fake-graph",
				components: []*inventory.Component{
					{Name: "libA", Version: "1.0", DetectionSource: "fake-graph"},
					{Name: "libB", Version: "2.0", DetectionSource: "fake-graph"},
				},
			},
			directNames: map[string]bool{"libA": true},
			edges:       map[string][]string{"libA": {"libB"}},
		},
	})

	result, err := e.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(result.Components))
	}

	a := findComponent(result.Components, "libA")
	b := findComponent(result.Components, "libB")
	if a == nil || b == nil {
		t.Fatal("expected both libA and libB")
	}
	if len(a.Dependencies) != 1 || a.Dependencies[0] != "libB" {
		t.Errorf("expected libA -> [libB], got %v", a.Dependencies)
	}
}

func TestEngine_MixedDetectors(t *testing.T) {
	e := New(".", false, []Detector{
		&fakeGraphDetector{
			fakeDetector: fakeDetector{
				name: "pkg-mgr",
				components: []*inventory.Component{
					{Name: "foo", Version: "1.0", DetectionSource: "pkg-mgr"},
				},
			},
			directNames: map[string]bool{"foo": true},
			edges:       make(map[string][]string),
		},
		&fakeDetector{
			name: "scanner",
			components: []*inventory.Component{
				{Name: "bar", Version: "2.0", DetectionSource: "scanner"},
			},
		},
	})

	result, err := e.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(result.Components))
	}
	if len(result.StrategiesUsed) != 2 {
		t.Errorf("expected 2 strategies, got %v", result.StrategiesUsed)
	}
}
