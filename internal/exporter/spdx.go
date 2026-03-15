package exporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tomBold/cpp-sbom-builder/internal/collector"
	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
)

type spdxDoc struct {
	SPDXVersion   string         `json:"spdxVersion"`
	DataLicense   string         `json:"dataLicense"`
	SPDXID        string         `json:"SPDXID"`
	Name          string         `json:"name"`
	CreationInfo  spdxCreation   `json:"creationInfo"`
	Packages      []spdxPackage  `json:"packages"`
}

type spdxCreation struct {
	Created string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

func WriteSPDX(result *collector.ScanResult, outputPath, toolVersion string, minConfidence float64) error {
	doc := buildSPDX(result, toolVersion, minConfidence)

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SPDX JSON: %w", err)
	}

	if outputPath == "-" {
		_, err = os.Stdout.Write(data)
		if err == nil {
			_, err = os.Stdout.WriteString("\n")
		}
		return err
	}

	return os.WriteFile(outputPath, append(data, '\n'), 0644)
}

func buildSPDX(result *collector.ScanResult, toolVersion string, minConfidence float64) spdxDoc {
	sorted := make([]*inventory.Component, 0, len(result.Components))
	for _, c := range result.Components {
		if minConfidence > 0 && SourceConfidence(c.DetectionSource) < minConfidence {
			continue
		}
		sorted = append(sorted, c)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	pkgs := make([]spdxPackage, 0, len(sorted))
	for i, c := range sorted {
		pkg := spdxPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-pkg-%d", i+1),
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: "NOASSERTION",
		}
		if c.Version == "" || c.Version == "unknown" {
			pkg.VersionInfo = ""
		}
		if c.PURL != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  c.PURL,
			}}
		}
		pkgs = append(pkgs, pkg)
	}

	return spdxDoc{
		SPDXVersion:  "SPDX-2.3",
		DataLicense:  "CC0-1.0",
		SPDXID:       "SPDXRef-DOCUMENT",
		Name:         "cpp-sbom-builder-" + strings.ReplaceAll(toolVersion, ".", "-"),
		CreationInfo: spdxCreation{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: cpp-sbom-builder-" + toolVersion},
		},
		Packages: pkgs,
	}
}
