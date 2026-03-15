package probers

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
)

func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "testdata", "fixtures")
}

func nameSet(comps []*inventory.Component) map[string]bool {
	m := make(map[string]bool, len(comps))
	for _, c := range comps {
		m[c.Name] = true
	}
	return m
}

func TestConanfileTxt_RequiresSection(t *testing.T) {
	strat := &ConanDetector{}
	result := strat.ScanWithGraph(testdataDir(), false)
	byName := nameSet(result.Components)
	for _, want := range []string{"boost", "openssl", "zlib", "nlohmann_json"} {
		if !byName[want] {
			t.Errorf("conanfile.txt: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestConanfileTxt_BuildRequiresSection(t *testing.T) {
	strat := &ConanDetector{}
	result := strat.ScanWithGraph(testdataDir(), false)
	byName := nameSet(result.Components)
	for _, want := range []string{"cmake", "ninja"} {
		if !byName[want] {
			t.Errorf("conanfile.txt [build_requires]: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestConanfileTxt_DirectNames(t *testing.T) {
	strat := &ConanDetector{}
	result := strat.ScanWithGraph(testdataDir(), false)
	for _, want := range []string{"boost", "openssl", "zlib", "nlohmann_json", "cmake", "ninja"} {
		if !result.DirectNames[want] {
			t.Errorf("conanfile.txt: %q should be in DirectNames; DirectNames=%v", want, result.DirectNames)
		}
	}
}

func TestConanfileTxt_ChannelAndRevision(t *testing.T) {
	txtPath := filepath.Join(testdataDir(), "conanfile.txt")
	comps, _ := parseConanfileTxtWithDirect(txtPath)
	for _, c := range comps {
		if c.Name == "openssl" {
			if c.Channel != "conan/stable" {
				t.Errorf("openssl channel = %q, want conan/stable", c.Channel)
			}
			if c.Version != "3.1.4" {
				t.Errorf("openssl version = %q, want 3.1.4", c.Version)
			}
		}
		if c.Name == "zlib" {
			if c.Revision != "abc123def456" {
				t.Errorf("zlib revision = %q, want abc123def456", c.Revision)
			}
		}
	}
}

func TestConanfilePy_ListSyntax(t *testing.T) {
	strat := &ConanDetector{}
	result := strat.ScanWithGraph(testdataDir(), false)
	byName := nameSet(result.Components)
	for _, want := range []string{"fmt", "spdlog"} {
		if !byName[want] {
			t.Errorf("conanfile.py list syntax: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestConanfilePy_PythonRequires(t *testing.T) {
	strat := &ConanDetector{}
	result := strat.ScanWithGraph(testdataDir(), false)
	byName := nameSet(result.Components)
	if !byName["cmake-conan"] {
		t.Errorf("conanfile.py python_requires: expected cmake-conan not found; got %v", keys(byName))
	}
}

func TestConanfilePy_RevisionInSelfRequires(t *testing.T) {
	strat := &ConanDetector{}
	result := strat.ScanWithGraph(testdataDir(), false)
	for _, c := range result.Components {
		if c.Name == "openssl" && c.Revision == "deadbeef1234" {
			return // found with correct revision
		}
	}
	t.Error("no openssl component with revision=deadbeef1234 from conanfile.py")
}

func TestConanLockV1_DirectVsTransitive(t *testing.T) {
	lockPath := filepath.Join(testdataDir(), "conan.lock")
	result := parseConanLockWithGraph(lockPath)
	if !result.DirectNames["boost"] {
		t.Errorf("boost should be direct; DirectNames=%v", result.DirectNames)
	}
	if !result.DirectNames["openssl"] {
		t.Errorf("openssl should be direct; DirectNames=%v", result.DirectNames)
	}
	if result.DirectNames["zlib"] {
		t.Error("zlib should be transitive (not in DirectNames)")
	}
}

func TestConanLockV1_Edges(t *testing.T) {
	lockPath := filepath.Join(testdataDir(), "conan.lock")
	result := parseConanLockWithGraph(lockPath)
	assertEdge(t, result.Edges, "boost", "zlib")
	assertEdge(t, result.Edges, "openssl", "zlib")
}

func TestConanLockV1_Revision(t *testing.T) {
	lockPath := filepath.Join(testdataDir(), "conan.lock")
	result := parseConanLockWithGraph(lockPath)
	for _, c := range result.Components {
		if c.Name == "boost" {
			if c.Revision != "rev001" {
				t.Errorf("boost revision = %q, want rev001", c.Revision)
			}
			return
		}
	}
	t.Error("boost not found in conan.lock")
}

func TestConanRef_Simple(t *testing.T) {
	c := conanRefToComponent("boost/1.82.0", "conan")
	if c == nil {
		t.Fatal("returned nil for simple ref")
	}
	if c.Name != "boost" || c.Version != "1.82.0" {
		t.Errorf("name=%q version=%q", c.Name, c.Version)
	}
	if c.Channel != "" || c.Revision != "" {
		t.Errorf("expected empty channel/revision, got channel=%q revision=%q", c.Channel, c.Revision)
	}
}

func TestConanRef_WithChannelAndRevision(t *testing.T) {
	c := conanRefToComponent("openssl/3.1.4@conan/stable#deadbeef", "conan")
	if c == nil {
		t.Fatal("returned nil")
	}
	if c.Channel != "conan/stable" {
		t.Errorf("channel = %q, want conan/stable", c.Channel)
	}
	if c.Revision != "deadbeef" {
		t.Errorf("revision = %q, want deadbeef", c.Revision)
	}
}

func TestConanRef_PlaceholderChannel(t *testing.T) {
	c := conanRefToComponent("boost/1.82.0@_/_", "conan")
	if c == nil {
		t.Fatal("returned nil")
	}
	if containsStr(c.PURL, "_/_") || containsStr(c.PURL, "?channel=") {
		t.Errorf("PURL %q should not contain placeholder channel", c.PURL)
	}
}

func TestConanRef_Invalid(t *testing.T) {
	if conanRefToComponent("notaref", "conan") != nil {
		t.Error("expected nil for invalid ref (no slash)")
	}
}

func TestHeaderScan_DetectsThirdParty(t *testing.T) {
	strat := &HeadersDetector{}
	comps, err := strat.Scan(testdataDir(), false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	byName := nameSet(comps)
	for _, want := range []string{"boost", "openssl", "nlohmann-json"} {
		if !byName[want] {
			t.Errorf("header-scan: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestHeaderScan_IgnoresStdlib(t *testing.T) {
	strat := &HeadersDetector{}
	comps, err := strat.Scan(testdataDir(), false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	byName := nameSet(comps)
	for _, bad := range []string{"vector", "string", "iostream", "algorithm", "cstdint"} {
		if byName[bad] {
			t.Errorf("header-scan: stdlib %q should not appear as a dependency", bad)
		}
	}
}

func TestHeaderScan_IgnoresInternalHeaders(t *testing.T) {
	strat := &HeadersDetector{}
	comps, err := strat.Scan(testdataDir(), false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	byName := nameSet(comps)
	if byName["internal_utils"] {
		t.Error("internal_utils.h should not be reported as a dependency")
	}
}

func TestHeaderScan_DetectionSource(t *testing.T) {
	strat := &HeadersDetector{}
	comps, _ := strat.Scan(testdataDir(), false)
	for _, c := range comps {
		if c.DetectionSource != "header-scan" {
			t.Errorf("%q has DetectionSource=%q, want header-scan", c.Name, c.DetectionSource)
		}
	}
}

func TestCompileCommands_DetectsExternalIncludes(t *testing.T) {
	strat := &CompileCommandsDetector{}
	comps, err := strat.Scan(testdataDir(), false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	byName := nameSet(comps)
	for _, want := range []string{"boost", "openssl", "zlib"} {
		if !byName[want] {
			t.Errorf("compile_commands: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestCompileCommands_ExtractsVersionFromPath(t *testing.T) {
	strat := &CompileCommandsDetector{}
	comps, _ := strat.Scan(testdataDir(), false)
	for _, c := range comps {
		switch c.Name {
		case "boost":
			if c.Version != "1.82.0" {
				t.Errorf("boost version = %q, want 1.82.0 (from path boost_1_82_0)", c.Version)
			}
		case "zlib":
			if c.Version != "1.2.13" {
				t.Errorf("zlib version = %q, want 1.2.13 (from path zlib-1.2.13)", c.Version)
			}
		}
	}
}

func TestExtractVersionFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/usr/local/include/boost_1_82_0", "1.82.0"},
		{"/opt/local/include/zlib-1.2.13", "1.2.13"},
		{"/usr/include/openssl-3.1.4", "3.1.4"},
		{"/usr/include/openssl", ""},
		{"/opt/fmt-10.1.1/include", "10.1.1"},
	}
	for _, tc := range cases {
		got := extractVersionFromPath(tc.path)
		if got != tc.want {
			t.Errorf("extractVersionFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestVcpkg_ManifestDetectsDependencies(t *testing.T) {
	strat := &VcpkgDetector{}
	comps, err := strat.Scan(testdataDir(), false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	byName := nameSet(comps)
	for _, want := range []string{"zlib", "libcurl", "sqlite3", "yaml-cpp"} {
		if !byName[want] {
			t.Errorf("vcpkg: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestVcpkg_DetectionSource(t *testing.T) {
	strat := &VcpkgDetector{}
	comps, _ := strat.Scan(testdataDir(), false)
	for _, c := range comps {
		if c.DetectionSource != "vcpkg" {
			t.Errorf("%q has DetectionSource=%q, want vcpkg", c.Name, c.DetectionSource)
		}
	}
}

func TestCMake_FindPackageAndFetchContent(t *testing.T) {
	strat := &CMakeDetector{}
	comps, err := strat.Scan(testdataDir(), false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	byName := nameSet(comps)
	for _, want := range []string{"openssl", "boost", "fmt"} {
		if !byName[want] {
			t.Errorf("cmake: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestCMake_DetectionSource(t *testing.T) {
	strat := &CMakeDetector{}
	comps, _ := strat.Scan(testdataDir(), false)
	for _, c := range comps {
		if c.DetectionSource != "cmake" {
			t.Errorf("%q has DetectionSource=%q, want cmake", c.Name, c.DetectionSource)
		}
	}
}

func TestParseLibraryFilename(t *testing.T) {
	cases := []struct {
		filename string
		wantName string
		wantVer  string
	}{
		{"libssl.so.3", "ssl", "3"},
		{"libboost_system.a", "boost_system", ""},
		{"libzlib-1.2.13.so", "zlib", "1.2.13"},
		{"libfmt.so", "fmt", ""},
	}
	for _, tc := range cases {
		gotName, gotVer := parseLibraryFilename(tc.filename)
		if gotName != tc.wantName {
			t.Errorf("parseLibraryFilename(%q) name=%q, want %q", tc.filename, gotName, tc.wantName)
		}
		if gotVer != tc.wantVer {
			t.Errorf("parseLibraryFilename(%q) ver=%q, want %q", tc.filename, gotVer, tc.wantVer)
		}
	}
}

func keys(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func assertEdge(t *testing.T, edges map[string][]string, parent, child string) {
	t.Helper()
	for _, c := range edges[parent] {
		if c == child {
			return
		}
	}
	t.Errorf("expected edge %s→%s; edges[%s]=%v", parent, child, parent, edges[parent])
}
