package exporter

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/tomBold/cpp-sbom-builder/internal/collector"
	"github.com/tomBold/cpp-sbom-builder/internal/probers"
	"github.com/tomBold/cpp-sbom-builder/internal/testutil"
)

func mustScan(t *testing.T) *collector.ScanResult {
	t.Helper()
	s := collector.New(testutil.DemoDir(), false, collector.DefaultDetectors())
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	return result
}

var purlRe = regexp.MustCompile(`^pkg:[a-z0-9]+/[^@]+(@[^?]+)?(\?.*)?$`)

func TestCycloneDX_ValidJSON(t *testing.T) {
	result := mustScan(t)
	bom := buildCycloneDX(result, "test", 0)

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	for _, field := range []string{"bomFormat", "specVersion", "version", "serialNumber", "metadata", "components"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing required field %q", field)
		}
	}
	if raw["bomFormat"] != "CycloneDX" || raw["specVersion"] != "1.5" {
		t.Errorf("bomFormat=%v specVersion=%v", raw["bomFormat"], raw["specVersion"])
	}

	comps, _ := raw["components"].([]interface{})
	if len(comps) == 0 {
		t.Error("expected at least one component")
	}
}

func TestCycloneDX_ComponentFields(t *testing.T) {
	result := mustScan(t)
	bom := buildCycloneDX(result, "test", 0)

	seenRefs := make(map[string]bool)
	for i := range bom.Components {
		c := &bom.Components[i]
		if c.Type != "library" {
			t.Errorf("component %q type = %q, want library", c.Name, c.Type)
		}
		if c.BOMRef == "" {
			t.Errorf("component %q has empty bom-ref", c.Name)
		}
		if seenRefs[c.BOMRef] {
			t.Errorf("duplicate bom-ref: %s", c.BOMRef)
		}
		seenRefs[c.BOMRef] = true

		if c.PURL != "" && !purlRe.MatchString(c.PURL) {
			t.Errorf("component %q invalid purl: %s", c.Name, c.PURL)
		}
	}
}

func TestCycloneDX_MinConfidenceFilter(t *testing.T) {
	result := mustScan(t)
	bomAll := buildCycloneDX(result, "test", 0.0)
	bomHigh := buildCycloneDX(result, "test", 0.85)

	if len(bomAll.Components) == 0 {
		t.Fatal("unfiltered BOM has no components")
	}
	if len(bomHigh.Components) >= len(bomAll.Components) {
		t.Errorf("expected filtering at 0.85 to remove low-confidence components: all=%d high=%d",
			len(bomAll.Components), len(bomHigh.Components))
	}
}

func TestCycloneDX_SourceConfidence(t *testing.T) {
	sources := []string{
		string(probers.DetectorConan),
		string(probers.DetectorVcpkg),
		string(probers.DetectorCompileCommands),
		string(probers.DetectorCMake),
		string(probers.DetectorBinaryScan),
		string(probers.DetectorHeaderScan),
		"unknown",
	}
	for _, src := range sources {
		c := collector.SourceConfidence(src)
		if c < 0 || c > 1 {
			t.Errorf("SourceConfidence(%q) = %f, must be in [0,1]", src, c)
		}
	}
}
