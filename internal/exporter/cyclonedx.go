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

type cdxBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Version      int             `json:"version"`
	SerialNumber string          `json:"serialNumber"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []cdxTool `json:"tools"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type        string        `json:"type"`
	BOMRef      string        `json:"bom-ref"`
	Name        string        `json:"name"`
	Version     string        `json:"version,omitempty"`
	Description string        `json:"description,omitempty"`
	PURL        string        `json:"purl,omitempty"`
	Properties  []cdxProperty `json:"properties,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func WriteCycloneDX(result *collector.ScanResult, outputPath, toolVersion string, minConfidence float64) error {
	bom := buildCycloneDX(result, toolVersion, minConfidence)

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CycloneDX JSON: %w", err)
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

func buildCycloneDX(result *collector.ScanResult, toolVersion string, minConfidence float64) cdxBOM {
	sorted := make([]*inventory.Component, 0, len(result.Components))
	for _, c := range result.Components {
		if minConfidence > 0 && collector.SourceConfidence(c.DetectionSource) < minConfidence {
			continue
		}
		sorted = append(sorted, c)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	bomRefByName := map[string]string{}
	for _, c := range sorted {
		bomRefByName[strings.ToLower(c.Name)] = c.BOMRef()
	}

	var cdxComps []cdxComponent
	for _, c := range sorted {
		cdxComps = append(cdxComps, cdxComponent{
			Type:        "library",
			BOMRef:      c.BOMRef(),
			Name:        c.Name,
			Version:     versionOrEmpty(c.Version),
			Description: c.Description,
			PURL:        c.PURL,
			Properties:  componentProperties(c),
		})
	}

	var deps []cdxDependency
	for _, c := range sorted {
		if len(c.Dependencies) == 0 {
			continue
		}
		var dependsOn []string
		for _, childName := range c.Dependencies {
			if ref, ok := bomRefByName[strings.ToLower(childName)]; ok {
				dependsOn = append(dependsOn, ref)
			}
		}
		if len(dependsOn) > 0 {
			sort.Strings(dependsOn)
			deps = append(deps, cdxDependency{Ref: c.BOMRef(), DependsOn: dependsOn})
		}
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })

	return cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		Version:      1,
		SerialNumber: generateURN(),
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{Vendor: "tomBold", Name: "cpp-sbom-builder", Version: toolVersion},
			},
		},
		Components:   cdxComps,
		Dependencies: deps,
	}
}

func componentProperties(c *inventory.Component) []cdxProperty {
	props := []cdxProperty{
		{Name: "cpp-sbom-builder:detectionSource", Value: c.DetectionSource},
		{Name: "cpp-sbom-builder:confidence", Value: fmt.Sprintf("%.2f", collector.SourceConfidence(c.DetectionSource))},
		{Name: "cpp-sbom-builder:dependencyType", Value: c.DependencyType()},
	}
	if c.Revision != "" {
		props = append(props, cdxProperty{Name: "cpp-sbom-builder:revision", Value: c.Revision})
	}
	if c.Channel != "" && c.Channel != "_/_" {
		props = append(props, cdxProperty{Name: "cpp-sbom-builder:channel", Value: c.Channel})
	}
	if len(c.IncludePaths) > 0 {
		props = append(props, cdxProperty{
			Name:  "cpp-sbom-builder:includePaths",
			Value: strings.Join(c.IncludePaths, "; "),
		})
	}
	if len(c.LinkLibraries) > 0 {
		props = append(props, cdxProperty{
			Name:  "cpp-sbom-builder:linkLibraries",
			Value: strings.Join(c.LinkLibraries, "; "),
		})
	}
	return props
}

func versionOrEmpty(v string) string {
	if v == "unknown" {
		return ""
	}
	return v
}

func generateURN() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		now&0xFFFFFFFF,
		(now>>32)&0xFFFF,
		0x4000|((now>>48)&0x0FFF),
		0x8000|(now&0x3FFF),
		now&0xFFFFFFFFFFFF,
	)
}
