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
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreation       `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
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
	sorted := collector.FilterByConfidence(result.Components, minConfidence)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	spdxIDByName := make(map[string]string, len(sorted))

	pkgs := make([]spdxPackage, 0, len(sorted))
	for i, c := range sorted {
		spdxID := fmt.Sprintf("SPDXRef-pkg-%d", i+1)
		spdxIDByName[strings.ToLower(c.Name)] = spdxID
		spdxIDByName[inventory.NormalizeKey(c.Name)] = spdxID

		pkg := spdxPackage{
			SPDXID:           spdxID,
			Name:             c.Name,
			VersionInfo:      c.Version,
			FilesAnalyzed:    false,
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

	rels := make([]spdxRelationship, 0, len(pkgs))
	for _, pkg := range pkgs {
		rels = append(rels, spdxRelationship{
			Element: "SPDXRef-DOCUMENT",
			Type:    "DESCRIBES",
			Related: pkg.SPDXID,
		})
	}

	for _, c := range sorted {
		if len(c.Dependencies) == 0 {
			continue
		}
		parentID := spdxIDByName[strings.ToLower(c.Name)]
		var childIDs []string
		for _, childName := range c.Dependencies {
			if childID, ok := spdxIDByName[inventory.NormalizeKey(childName)]; ok {
				childIDs = append(childIDs, childID)
			}
		}
		sort.Strings(childIDs)
		for _, childID := range childIDs {
			rels = append(rels, spdxRelationship{
				Element: parentID,
				Type:    "DEPENDS_ON",
				Related: childID,
			})
		}
	}

	docName := result.ProjectName
	if docName == "" {
		docName = "unknown-project"
	}

	return spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              docName,
		DocumentNamespace: fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s", docName, generateURN()),
		CreationInfo: spdxCreation{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: cpp-sbom-builder-" + toolVersion},
		},
		Packages:      pkgs,
		Relationships: rels,
	}
}
