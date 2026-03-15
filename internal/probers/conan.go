package probers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/registry"
	"github.com/tomBold/cpp-sbom-builder/internal/slices"
)

type ConanDetector struct{}

func (s *ConanDetector) Name() string { return "conan" }

type conanLockV1 struct {
	GraphLock struct {
		Nodes map[string]conanLockV1Node `json:"nodes"`
	} `json:"graph_lock"`
}

type conanLockV1Node struct {
	Ref      string   `json:"ref"`
	Requires []string `json:"requires"`
}

var reConanRef = regexp.MustCompile(`^([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^\s#]*)?(?:#([A-Za-z0-9\-_]+))?$`)

var reConanfileTxtRequires = regexp.MustCompile(`^\s*([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^\s#]*)?(?:#([A-Za-z0-9\-_]+))?`)

var reConanfilePyRequires = regexp.MustCompile(`(?:self\.requires|self\.build_requires|self\.test_requires|self\.tool_requires)\s*\(\s*["']([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^#"']*)?(?:#([A-Za-z0-9\-_]+))?[^"']*["']`)

var reConanfilePyPythonRequires = regexp.MustCompile(`python_requires\s*=\s*["']([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^#"']*)?(?:#([A-Za-z0-9\-_]+))?[^"']*["']`)

type ConanScanResult struct {
	Components  []*inventory.Component
	DirectNames map[string]bool
	Edges       map[string][]string
}

func (s *ConanDetector) Scan(projectRoot string, verbose bool) ([]*inventory.Component, error) {
	return s.ScanWithGraph(projectRoot, verbose).Components, nil
}

// ScanGraph satisfies collector.GraphDetector, returning components
// together with dependency edges and direct-dependency classification.
func (s *ConanDetector) ScanGraph(projectRoot string, verbose bool) ([]*inventory.Component, map[string]bool, map[string][]string) {
	r := s.ScanWithGraph(projectRoot, verbose)
	return r.Components, r.DirectNames, r.Edges
}

func (s *ConanDetector) ScanWithGraph(projectRoot string, verbose bool) *ConanScanResult {
	result := &ConanScanResult{
		DirectNames: map[string]bool{},
		Edges:       map[string][]string{},
	}

	_ = filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".git") || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		switch strings.ToLower(d.Name()) {
		case "conan.lock":
			if verbose {
				fmt.Printf("  [conan] Parsing conan.lock: %s\n", path)
			}
			lr := parseConanLockWithGraph(path)
			result.Components = append(result.Components, lr.Components...)
			for k, v := range lr.DirectNames {
				result.DirectNames[k] = v
			}
			for k, v := range lr.Edges {
				result.Edges[k] = append(result.Edges[k], v...)
			}

		case "conanfile.txt":
			if verbose {
				fmt.Printf("  [conan] Parsing conanfile.txt: %s\n", path)
			}
			comps, directNames := parseConanfileTxtWithDirect(path)
			result.Components = append(result.Components, comps...)
			for k, v := range directNames {
				result.DirectNames[k] = v
			}

		case "conanfile.py":
			if verbose {
				fmt.Printf("  [conan] Parsing conanfile.py: %s\n", path)
			}
			comps, directNames := parseConanfilePyWithDirect(path)
			result.Components = append(result.Components, comps...)
			for k, v := range directNames {
				result.DirectNames[k] = v
			}
		}
		return nil
	})

	return result
}

type lockGraphResult struct {
	Components  []*inventory.Component
	DirectNames map[string]bool
	Edges       map[string][]string
}

func parseConanLockWithGraph(path string) *lockGraphResult {
	data, err := os.ReadFile(path)
	if err != nil {
		return &lockGraphResult{DirectNames: map[string]bool{}, Edges: map[string][]string{}}
	}

	result := &lockGraphResult{
		DirectNames: map[string]bool{},
		Edges:       map[string][]string{},
	}

	var v1 conanLockV1
	if err := json.Unmarshal(data, &v1); err == nil && len(v1.GraphLock.Nodes) > 0 {
		nodeNames := map[string]string{}
		for idx, node := range v1.GraphLock.Nodes {
			if node.Ref == "" {
				continue
			}
			c := conanRefToComponent(node.Ref, "conan")
			if c == nil {
				continue
			}
			nodeNames[idx] = c.Name
			result.Components = append(result.Components, c)
		}
		for idx, node := range v1.GraphLock.Nodes {
			parentName := nodeNames[idx]
			if parentName == "" {
				continue
			}
			for _, req := range node.Requires {
				reqBase := strings.SplitN(req, "#", 2)[0]
				childName := nodeNames[reqBase]
				if childName != "" && childName != parentName {
					result.Edges[parentName] = slices.AppendUnique(result.Edges[parentName], childName)
				}
			}
			if idx == "0" {
				for _, req := range node.Requires {
					reqBase := strings.SplitN(req, "#", 2)[0]
					if childName := nodeNames[reqBase]; childName != "" {
						result.DirectNames[childName] = true
					}
				}
			}
		}
		return result
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		for _, key := range []string{"requires", "build_requires", "test_requires", "tool_requires"} {
			if reqRaw, ok := raw[key]; ok {
				var refs []string
				if err := json.Unmarshal(reqRaw, &refs); err == nil {
					for _, ref := range refs {
						c := conanRefToComponent(ref, "conan")
						if c != nil {
							result.Components = append(result.Components, c)
							result.DirectNames[c.Name] = true
						}
					}
				}
			}
		}
	}

	return result
}

func parseConanfileTxtWithDirect(path string) ([]*inventory.Component, map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var components []*inventory.Component
	directNames := map[string]bool{}

	type sectionKind int
	const (
		sectionNone sectionKind = iota
		sectionRequires
	)
	currentSection := sectionNone

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[requires]", "[build_requires]", "[test_requires]", "[tool_requires]":
				currentSection = sectionRequires
			default:
				currentSection = sectionNone
			}
			continue
		}
		if currentSection == sectionNone {
			continue
		}
		if m := reConanfileTxtRequires.FindStringSubmatch(line); m != nil {
			channel := strings.TrimPrefix(m[3], "@")
			revision := m[4]
			c := makeConanComponent(m[1], m[2], channel, revision, "conan")
			components = append(components, c)
			directNames[c.Name] = true
		}
	}
	return components, directNames
}

func stripPythonComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			b.WriteByte('\n')
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func parseConanfilePyWithDirect(path string) ([]*inventory.Component, map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	content := stripPythonComments(string(data))

	var components []*inventory.Component
	directNames := map[string]bool{}

	for _, m := range reConanfilePyRequires.FindAllStringSubmatch(content, -1) {
		c := makeConanComponent(m[1], m[2], strings.TrimPrefix(m[3], "@"), m[4], "conan")
		components = append(components, c)
		directNames[c.Name] = true
	}

	for _, m := range reConanfilePyPythonRequires.FindAllStringSubmatch(content, -1) {
		c := makeConanComponent(m[1], m[2], strings.TrimPrefix(m[3], "@"), m[4], "conan")
		components = append(components, c)
		directNames[c.Name] = true
	}

	reList := regexp.MustCompile(`(?i)(?:^|\s)requires\s*=\s*\[([^\]]+)\]`)
	if lm := reList.FindStringSubmatch(content); lm != nil {
		reItem := regexp.MustCompile(`["']([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^#"']*)?(?:#([a-f0-9\-_]+))?[^"']*["']`)
		for _, im := range reItem.FindAllStringSubmatch(lm[1], -1) {
			c := makeConanComponent(im[1], im[2], strings.TrimPrefix(im[3], "@"), im[4], "conan")
			components = append(components, c)
			directNames[c.Name] = true
		}
	}

	return components, directNames
}

func conanRefToComponent(ref, source string) *inventory.Component {
	m := reConanRef.FindStringSubmatch(strings.TrimSpace(ref))
	if m == nil {
		return nil
	}
	return makeConanComponent(m[1], m[2], strings.TrimPrefix(m[3], "@"), m[4], source)
}

func makeConanComponent(name, version, channel, revision, source string) *inventory.Component {
	entry := registry.Identify(name)
	purl := "pkg:conan/" + name + "@" + version
	desc := ""
	if entry != nil {
		purl = entry.PURLPrefix + "@" + version
		desc = entry.Description
	}
	if channel != "" && channel != "_/_" && channel != "@_/_" {
		purl += "?channel=" + strings.ReplaceAll(channel, "/", "%2F")
	}
	return &inventory.Component{
		Name:            name,
		Version:         version,
		PURL:            purl,
		Revision:        revision,
		Channel:         channel,
		DetectionSource: source,
		Description:     desc,
	}
}
