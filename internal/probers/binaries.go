package probers

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/registry"
	"github.com/tomBold/cpp-sbom-builder/internal/slices"
)

type BinariesDetector struct{}

func (s *BinariesDetector) Name() string { return string(DetectorBinaryScan) }

var binaryExts = map[string]bool{
	".so": true, ".a": true, ".dll": true, ".lib": true, ".dylib": true,
}

var reSharedLibName = regexp.MustCompile(`^lib([A-Za-z0-9_\-]+?)(?:[-_](\d+\.\d+(?:\.\d+)?))?\.(?:so|dylib|dll)`)

var reStaticLibName = regexp.MustCompile(`^lib([A-Za-z0-9_\-]+?)(?:[-_](\d+\.\d+(?:\.\d+)?))?\.(?:a|lib)$`)

var reSoVersion = regexp.MustCompile(`\.so\.(\d+(?:\.\d+)*)`)

var reDLLVersion = regexp.MustCompile(`^([A-Za-z0-9_\-]+?)[-_](\d+\.\d+(?:\.\d+)?)$`)

func (s *BinariesDetector) Scan(projectRoot string, verbose bool) ([]*inventory.Component, error) {
	seen := map[string]*inventory.Component{}
	unknown := map[string]bool{}
	fileCount := 0

	WalkProject(projectRoot, nil, func(path string, d os.DirEntry) {
		filename := d.Name()
		ext := strings.ToLower(filepath.Ext(filename))
		isSOWithVersion := strings.Contains(strings.ToLower(filename), ".so.")

		if !binaryExts[ext] && !isSOWithVersion {
			return
		}

		fileCount++
		detectBinaryComponent(filename, seen, unknown)
	})

	if verbose {
		fmt.Printf("  [%s] Scanned %d binary artifact(s), found %d components\n", DetectorBinaryScan, fileCount, len(seen))
		for name := range unknown {
			fmt.Printf("  [%s] Unknown library: %q (not in catalog, skipped)\n", DetectorBinaryScan, name)
		}
	}

	result := make([]*inventory.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result, nil
}

func detectBinaryComponent(filename string, seen map[string]*inventory.Component, unknown map[string]bool) {
	name, version := parseLibraryFilename(filename)
	if name == "" {
		return
	}

	lib := registry.Identify(name)
	if lib == nil {
		lib = registry.Identify(filename)
	}
	if lib == nil {
		unknown[name] = true
		return
	}

	key := lib.Name
	c, ok := seen[key]
	if !ok {
		purl := lib.PURLPrefix
		if version != "" {
			purl += "@" + version
		}
		c = &inventory.Component{
			Name:            lib.Name,
			Version:         version,
			PURL:            purl,
			DetectionSource: string(DetectorBinaryScan),
			Description:     lib.Description,
		}
		if c.Version == "" {
			c.Version = "unknown"
		}
		seen[key] = c
	} else {
		if c.Version == "unknown" && version != "" {
			c.Version = version
			c.PURL = lib.PURLPrefix + "@" + version
		}
	}
	c.LinkLibraries = slices.AppendUnique(c.LinkLibraries, filename)
}

func parseLibraryFilename(filename string) (name, version string) {
	lower := strings.ToLower(filename)

	if m := reSoVersion.FindStringSubmatch(lower); m != nil {
		base := lower[:strings.Index(lower, ".so")]
		base = strings.TrimPrefix(base, "lib")
		if i := strings.LastIndexAny(base, "-_"); i > 0 {
			if isVersionLike(base[i+1:]) {
				return base[:i], m[1]
			}
		}
		return base, m[1]
	}

	if m := reSharedLibName.FindStringSubmatch(lower); m != nil {
		return m[1], m[2]
	}

	if m := reStaticLibName.FindStringSubmatch(lower); m != nil {
		return m[1], m[2]
	}

	if strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".lib") {
		base := lower[:strings.LastIndex(lower, ".")]
		if m := reDLLVersion.FindStringSubmatch(base); m != nil {
			return m[1], m[2]
		}
		return base, ""
	}

	return "", ""
}

func isVersionLike(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
