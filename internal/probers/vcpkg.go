package probers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/registry"
)

type VcpkgDetector struct{}

func (s *VcpkgDetector) Name() string { return string(DetectorVcpkg) }

type vcpkgDependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type vcpkgLock struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

func (s *VcpkgDetector) Scan(projectRoot string, verbose bool) ([]*inventory.Component, error) {
	var components []*inventory.Component

	WalkProject(projectRoot, nil, func(path string, d os.DirEntry) {
		switch strings.ToLower(d.Name()) {
		case "vcpkg.json":
			if verbose {
				fmt.Printf("  [%s] Parsing vcpkg.json: %s\n", DetectorVcpkg, path)
			}
			components = append(components, parseVcpkgManifest(path)...)

		case "vcpkg-lock.json":
			if verbose {
				fmt.Printf("  [%s] Parsing vcpkg-lock.json: %s\n", DetectorVcpkg, path)
			}
			components = append(components, parseVcpkgLock(path)...)

		case "status":
			if strings.Contains(filepath.ToSlash(path), "vcpkg") {
				if verbose {
					fmt.Printf("  [%s] Parsing vcpkg status: %s\n", DetectorVcpkg, path)
				}
				components = append(components, parseVcpkgStatus(path)...)
			}
		}
	})

	return components, nil
}

func parseVcpkgManifest(path string) []*inventory.Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw struct {
		Dependencies []json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var components []*inventory.Component
	for _, dep := range raw.Dependencies {
		var name string
		if err := json.Unmarshal(dep, &name); err == nil {
			components = append(components, makeVcpkgComponent(name, "unknown"))
			continue
		}
		var obj vcpkgDependency
		if err := json.Unmarshal(dep, &obj); err == nil && obj.Name != "" {
			components = append(components, makeVcpkgComponent(obj.Name, obj.Version))
		}
	}
	return components
}

func parseVcpkgLock(path string) []*inventory.Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var lock vcpkgLock
	if err := json.Unmarshal(data, &lock); err == nil && len(lock.Packages) > 0 {
		var components []*inventory.Component
		for name, pkg := range lock.Packages {
			name = strings.SplitN(name, ":", 2)[0] // strip triplet suffix
			components = append(components, makeVcpkgComponent(name, pkg.Version))
		}
		return components
	}

	var arr []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &arr); err == nil {
		var components []*inventory.Component
		for _, item := range arr {
			if item.Name != "" {
				components = append(components, makeVcpkgComponent(item.Name, item.Version))
			}
		}
		return components
	}
	return nil
}

func parseVcpkgStatus(path string) []*inventory.Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var components []*inventory.Component
	var curName, curVersion string
	installed := false

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if installed && curName != "" {
				components = append(components, makeVcpkgComponent(curName, curVersion))
			}
			curName, curVersion, installed = "", "", false
			continue
		}
		switch {
		case strings.HasPrefix(line, "Package:"):
			curName = strings.SplitN(strings.TrimSpace(strings.TrimPrefix(line, "Package:")), ":", 2)[0]
		case strings.HasPrefix(line, "Version:"):
			curVersion = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Status:") && strings.Contains(line, "installed"):
			installed = true
		}
	}
	if installed && curName != "" {
		components = append(components, makeVcpkgComponent(curName, curVersion))
	}
	return components
}

func makeVcpkgComponent(name, version string) *inventory.Component {
	if version == "" {
		version = "unknown"
	}
	lib := registry.Identify(name)
	canonicalName := name
	purl := "pkg:generic/" + name
	if version != "unknown" {
		purl += "@" + version
	}
	desc := ""
	if lib != nil {
		canonicalName = lib.Name
		purl = lib.PURLPrefix
		if version != "unknown" {
			purl += "@" + version
		}
		desc = lib.Description
	}
	return &inventory.Component{
		Name:            canonicalName,
		Version:         version,
		PURL:            purl,
		DetectionSource: string(DetectorVcpkg),
		Description:     desc,
	}
}
