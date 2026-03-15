package exporter

import (
	"encoding/json"
	"regexp"
	"testing"
)

func TestSPDX_ValidJSON(t *testing.T) {
	result := mustScan(t)
	doc := buildSPDX(result, "test", 0)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("SPDX output is not valid JSON: %v", err)
	}

	for _, field := range []string{"spdxVersion", "SPDXID", "dataLicense", "name", "creationInfo", "packages"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing required field %q", field)
		}
	}
	if raw["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v, want SPDX-2.3", raw["spdxVersion"])
	}

	pkgs, _ := raw["packages"].([]interface{})
	if len(pkgs) == 0 {
		t.Error("expected at least one package")
	}
}

func TestSPDX_PackageFields(t *testing.T) {
	result := mustScan(t)
	doc := buildSPDX(result, "test", 0)

	spdxIDRe := regexp.MustCompile(`^SPDXRef-pkg-\d+$`)
	seenIDs := make(map[string]bool)
	for _, pkg := range doc.Packages {
		if !spdxIDRe.MatchString(pkg.SPDXID) {
			t.Errorf("package %q invalid SPDXID: %s", pkg.Name, pkg.SPDXID)
		}
		if seenIDs[pkg.SPDXID] {
			t.Errorf("duplicate SPDXID: %s", pkg.SPDXID)
		}
		seenIDs[pkg.SPDXID] = true

		if pkg.DownloadLocation != "NOASSERTION" {
			t.Errorf("package %q downloadLocation = %q, want NOASSERTION", pkg.Name, pkg.DownloadLocation)
		}
		if len(pkg.ExternalRefs) > 0 {
			ref := pkg.ExternalRefs[0]
			if ref.ReferenceType != "purl" || ref.ReferenceCategory != "PACKAGE-MANAGER" {
				t.Errorf("package %q invalid externalRef: %+v", pkg.Name, ref)
			}
			if ref.ReferenceLocator == "" {
				t.Errorf("package %q empty purl locator", pkg.Name)
			}
		}
	}
}

func TestSPDX_MinConfidenceFilter(t *testing.T) {
	result := mustScan(t)
	docAll := buildSPDX(result, "test", 0.0)
	docHigh := buildSPDX(result, "test", 0.85)

	if len(docAll.Packages) == 0 {
		t.Fatal("unfiltered SPDX doc has no packages")
	}
	if len(docHigh.Packages) >= len(docAll.Packages) {
		t.Errorf("expected filtering at 0.85 to remove low-confidence packages: all=%d high=%d",
			len(docAll.Packages), len(docHigh.Packages))
	}
}

func TestSPDX_ConsistentWithCycloneDX(t *testing.T) {
	result := mustScan(t)
	cdxBom := buildCycloneDX(result, "test", 0)
	spdxDoc := buildSPDX(result, "test", 0)

	if len(cdxBom.Components) != len(spdxDoc.Packages) {
		t.Errorf("CycloneDX has %d components, SPDX has %d packages (should match)", len(cdxBom.Components), len(spdxDoc.Packages))
	}
}

func TestSPDX_DependsOnRelationships(t *testing.T) {
	result := mustScan(t)
	doc := buildSPDX(result, "test", 0)

	hasDependsOn := false
	for _, rel := range doc.Relationships {
		if rel.Type == "DEPENDS_ON" {
			hasDependsOn = true
			if rel.Element == "SPDXRef-DOCUMENT" {
				t.Error("DEPENDS_ON should not originate from SPDXRef-DOCUMENT")
			}
			if rel.Related == "" {
				t.Error("DEPENDS_ON has empty relatedSpdxElement")
			}
		}
	}

	hasDeps := false
	for _, c := range result.Components {
		if len(c.Dependencies) > 0 {
			hasDeps = true
			break
		}
	}
	if hasDeps && !hasDependsOn {
		t.Error("scan result has dependency edges but SPDX doc has no DEPENDS_ON relationships")
	}
}
