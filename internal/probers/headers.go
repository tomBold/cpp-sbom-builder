package probers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/pathutil"
	"github.com/tomBold/cpp-sbom-builder/internal/registry"
	"github.com/tomBold/cpp-sbom-builder/internal/slices"
)

type HeadersDetector struct{}

func (s *HeadersDetector) Name() string { return string(DetectorHeaderScan) }

var (
	reInclude      = regexp.MustCompile(`^\s*#\s*include\s*([<"])([^>"]+)[>"]`)
	reVersionMacro = regexp.MustCompile(`(?i)#\s*define\s+[A-Z_]*VERSION[A-Z_]*\s+"?([\d][.\d]+)"?`)
)

var sourceExts = map[string]bool{
	".cpp": true, ".cc": true, ".cxx": true, ".c++": true,
	".c": true,
	".h": true, ".hpp": true, ".hxx": true, ".h++": true, ".hh": true,
	".inl": true, ".ipp": true, ".tpp": true,
}

var headerExtraDirs = map[string]bool{
	"CMakeFiles": true, "build": true, "out": true, "_build": true,
	".build": true, "third_party": true, "external": true, "extern": true,
	"bazel-bin": true, "bazel-out": true, "bazel-testlogs": true,
}

type headerLocal struct {
	seen    map[string]*inventory.Component
	unknown map[string]bool
	count   int
}

func (s *HeadersDetector) Scan(projectRoot string, verbose bool) ([]*inventory.Component, error) {
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}

	fileCh := make(chan string, numWorkers*4)
	locals := make([]headerLocal, numWorkers)

	var statMu sync.RWMutex
	statCache := map[string]bool{}

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			l := headerLocal{
				seen:    map[string]*inventory.Component{},
				unknown: map[string]bool{},
			}
			for path := range fileCh {
				l.count++
				extractIncludesFromFile(path, projectRoot, l.seen, l.unknown, statCache, &statMu)
			}
			locals[idx] = l
		}(i)
	}

	WalkProject(projectRoot, headerExtraDirs, func(path string, d os.DirEntry) {
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !sourceExts[ext] {
			return
		}
		fileCh <- path
	})
	close(fileCh)
	wg.Wait()

	seen := map[string]*inventory.Component{}
	unknown := map[string]bool{}
	fileCount := 0
	for _, l := range locals {
		fileCount += l.count
		for k := range l.unknown {
			unknown[k] = true
		}
		for name, c := range l.seen {
			if existing, ok := seen[name]; ok {
				for _, p := range c.IncludePaths {
					existing.IncludePaths = slices.AppendUnique(existing.IncludePaths, p)
				}
			} else {
				seen[name] = c
			}
		}
	}

	if verbose {
		fmt.Printf("  [%s] Scanned %d source/header files, found %d components\n", DetectorHeaderScan, fileCount, len(seen))
		for name := range unknown {
			fmt.Printf("  [%s] Unknown library: %q (not in catalog, skipped)\n", DetectorHeaderScan, name)
		}
	}

	result := make([]*inventory.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result, nil
}

func extractIncludesFromFile(path, projectRoot string, seen map[string]*inventory.Component, unknown map[string]bool, statCache map[string]bool, statMu *sync.RWMutex) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		m := reInclude.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		bracket := m[1]
		include := m[2]

		if bracket == `"` {
			if !filepath.IsAbs(include) {
				continue
			}
		}

		if registry.IsSystemHeader(include) {
			continue
		}

		if isInternalInclude(include, path, projectRoot, statCache, statMu) {
			continue
		}

		entry := registry.Identify(include)
		if entry == nil {
			unknown[include] = true
			continue
		}

		c, ok := seen[entry.Name]
		if !ok {
			c = &inventory.Component{
				Name:            entry.Name,
				Version:         "unknown",
				PURL:            entry.PURLPrefix,
				DetectionSource: string(DetectorHeaderScan),
				Description:     entry.Description,
			}
			seen[entry.Name] = c
		}
		c.IncludePaths = slices.AppendUnique(c.IncludePaths, include)
	}
}

func isInternalInclude(include, sourceFile, projectRoot string, statCache map[string]bool, statMu *sync.RWMutex) bool {
	sourceDir := filepath.Dir(sourceFile)
	candidates := []string{
		filepath.Join(sourceDir, include),
		filepath.Join(projectRoot, include),
		filepath.Join(projectRoot, "include", include),
		filepath.Join(projectRoot, "src", include),
		filepath.Join(projectRoot, "lib", include),
	}
	for _, candidate := range candidates {
		if !pathutil.IsUnderRoot(candidate, projectRoot) {
			continue
		}
		statMu.RLock()
		exists, cached := statCache[candidate]
		statMu.RUnlock()
		if cached {
			if exists {
				return true
			}
			continue
		}
		_, err := os.Stat(candidate)
		statMu.Lock()
		statCache[candidate] = err == nil
		statMu.Unlock()
		if err == nil {
			return true
		}
	}
	return false
}

func ScanVersionHints(components []*inventory.Component, projectRoot string) {
	for _, c := range components {
		if c.Version != "unknown" {
			continue
		}
		for _, incPath := range c.IncludePaths {
			resolved := incPath
			if !filepath.IsAbs(incPath) {
				resolved = filepath.Join(projectRoot, incPath)
			}
			abs, err := filepath.Abs(resolved)
			if err != nil || pathutil.RejectPath(abs) || !pathutil.IsUnderRoot(abs, projectRoot) {
				continue
			}
			v := findVersionInDir(abs, projectRoot)
			if v != "" {
				c.Version = v
				if strings.Contains(c.PURL, "@") {
					parts := strings.SplitN(c.PURL, "@", 2)
					c.PURL = parts[0] + "@" + v
				} else {
					c.PURL = c.PURL + "@" + v
				}
				break
			}
		}
	}
}

func findVersionInDir(path, projectRoot string) string {
	if pathutil.RejectPath(path) || !pathutil.IsUnderRoot(path, projectRoot) {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if !info.IsDir() {
		return findVersionInFile(path, projectRoot)
	}

	for _, vf := range []string{"version.h", "version.hpp", "Version.h", "config.h", "config.hpp"} {
		p := filepath.Join(path, vf)
		if pathutil.IsUnderRoot(p, projectRoot) {
			if v := findVersionInFile(p, projectRoot); v != "" {
				return v
			}
		}
	}

	var foundVersion string
	_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !pathutil.IsUnderRoot(p, projectRoot) {
			return nil
		}
		lname := strings.ToLower(d.Name())
		if strings.Contains(lname, "version") || strings.Contains(lname, "config") {
			if v := findVersionInFile(p, projectRoot); v != "" {
				foundVersion = v
				return filepath.SkipAll
			}
		}
		return nil
	})
	return foundVersion
}

func findVersionInFile(path, projectRoot string) string {
	if pathutil.RejectPath(path) || !pathutil.IsUnderRoot(path, projectRoot) {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := reVersionMacro.FindStringSubmatch(sc.Text()); m != nil {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}
