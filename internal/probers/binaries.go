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

func (s *BinariesDetector) Name() string { return "binary-scan" }

var binaryExts = map[string]bool{
	".so": true, ".a": true, ".dll": true, ".lib": true, ".dylib": true,
}

var reSharedLibName = regexp.MustCompile(`^lib([A-Za-z0-9_\-]+?)(?:[-_](\d+\.\d+(?:\.\d+)?))?\.(?:so|dylib|dll)`)

var reStaticLibName = regexp.MustCompile(`^lib([A-Za-z0-9_\-]+?)(?:[-_](\d+\.\d+(?:\.\d+)?))?\.(?:a|lib)$`)

var reSoVersion = regexp.MustCompile(`\.so\.(\d+(?:\.\d+)*)`)

func (s *BinariesDetector) Scan(projectRoot string, verbose bool) ([]*inventory.Component, error) {
	seen := map[string]*inventory.Component{}
	fileCount := 0

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

		filename := d.Name()
		ext := strings.ToLower(filepath.Ext(filename))
		isSOWithVersion := strings.Contains(strings.ToLower(filename), ".so.")

		if !binaryExts[ext] && !isSOWithVersion {
			return nil
		}

		fileCount++
		detectBinaryComponent(filename, seen)
		return nil
	})

	if verbose {
		fmt.Printf("  [binary-scan] Scanned %d binary artifact(s), found %d components\n", fileCount, len(seen))
	}

	result := make([]*inventory.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result, nil
}

func detectBinaryComponent(filename string, seen map[string]*inventory.Component) {
	name, version := parseLibraryFilename(filename)
	if name == "" {
		return
	}

	lib := registry.Identify(name)
	if lib == nil {
		lib = registry.Identify(filename)
	}
	if lib == nil {
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
			DetectionSource: "binary-scan",
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
		reVer := regexp.MustCompile(`^([A-Za-z0-9_\-]+?)[-_](\d+\.\d+(?:\.\d+)?)$`)
		if m := reVer.FindStringSubmatch(base); m != nil {
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

func BinaryStubForTesting(dir, soname string) error {
	path := filepath.Join(dir, soname)
	return os.WriteFile(path, []byte("stub"), 0644)
}
