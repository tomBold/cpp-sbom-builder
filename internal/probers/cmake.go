package probers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/registry"
	"github.com/tomBold/cpp-sbom-builder/internal/slices"
)

type CMakeDetector struct{}

func (s *CMakeDetector) Name() string { return "cmake" }

var (
	reFindPackage  = regexp.MustCompile(`(?i)find_package\s*\(\s*([A-Za-z0-9_\-]+)`)
	reFetchContent = regexp.MustCompile(`(?i)FetchContent_Declare\s*\(\s*([A-Za-z0-9_\-]+)`)
	reLibToken     = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_]+)::([A-Za-z0-9_]+)`)
	reCacheDir     = regexp.MustCompile(`(?i)^([A-Za-z0-9_]+)(?:_DIR|_INCLUDE_DIR|_INCLUDE_DIRS|_ROOT):(?:PATH|STRING|FILEPATH)\s*=\s*(.+)$`)
	reCacheLib     = regexp.MustCompile(`(?i)^([A-Za-z0-9_]+)(?:_LIBRARIES|_LIBRARY|_LIB):(?:FILEPATH|STRING)\s*=\s*(.+)$`)
	reCacheVersion = regexp.MustCompile(`(?i)^([A-Za-z0-9_]+)_VERSION(?:_STRING)?:STRING\s*=\s*(.+)$`)
	reGitTag       = regexp.MustCompile(`(?i)GIT_TAG\s+([^\s)]+)`)
)

var cmakeBuiltins = map[string]bool{
	"Threads": true, "OpenMP": true, "MPI": true, "CUDA": true,
	"CUDAToolkit": true, "Python": true, "Python3": true, "Python2": true,
	"PkgConfig": true, "GNUInstallDirs": true, "CMakePackageConfigHelpers": true,
	"CheckCXXCompilerFlag": true, "CheckCCompilerFlag": true,
	"CheckIncludeFile": true, "CheckIncludeFileCXX": true,
	"CheckFunctionExists": true, "CheckLibraryExists": true,
	"CheckSymbolExists": true, "CheckTypeSize": true,
	"ExternalProject": true, "FetchContent": true,
	"CTest": true, "CPack": true, "InstallRequiredSystemLibraries": true,
	"GenerateExportHeader": true, "WriteCompilerDetectionHeader": true,
}

func (s *CMakeDetector) Scan(projectRoot string, verbose bool) ([]*inventory.Component, error) {
	seen := map[string]*inventory.Component{}
	versions := map[string]string{}

	for _, rel := range []string{
		"CMakeCache.txt", "build/CMakeCache.txt", "out/CMakeCache.txt",
		"cmake-build-debug/CMakeCache.txt", "cmake-build-release/CMakeCache.txt",
	} {
		cf := filepath.Join(projectRoot, rel)
		if _, err := os.Stat(cf); err == nil {
			if verbose {
				fmt.Printf("  [cmake] Parsing CMakeCache.txt: %s\n", cf)
			}
			parseCMakeCache(cf, projectRoot, seen, versions)
		}
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
		if strings.EqualFold(d.Name(), "CMakeLists.txt") {
			if verbose {
				fmt.Printf("  [cmake] Parsing CMakeLists.txt: %s\n", path)
			}
			parseCMakeLists(path, seen, versions)
		}
		return nil
	})

	for name, c := range seen {
		if c.Version == "unknown" {
			if v, ok := versions[strings.ToLower(name)]; ok && v != "" {
				c.Version = v
				if entry := registry.Identify(name); entry != nil {
					c.PURL = entry.PURLPrefix + "@" + v
				}
			}
		}
	}

	result := make([]*inventory.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result, nil
}

func parseCMakeCache(path, projectRoot string, seen map[string]*inventory.Component, versions map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		if m := reCacheVersion.FindStringSubmatch(line); m != nil {
			ver := strings.TrimSpace(m[2])
			if ver != "" && ver != "ver-NOTFOUND" {
				versions[strings.ToLower(m[1])] = ver
			}
		}

		if m := reCacheDir.FindStringSubmatch(line); m != nil {
			dirPath := strings.TrimSpace(m[2])
			if dirPath == "" || strings.HasSuffix(dirPath, "-NOTFOUND") {
				continue
			}
			if !isExternalPath(dirPath, projectRoot) {
				continue
			}
			entry := registry.Identify(m[1])
			if entry == nil {
				entry = registry.Identify(dirPath)
			}
			if entry != nil {
				upsertComponent(seen, entry, dirPath, "", "cmake")
			}
		}

		if m := reCacheLib.FindStringSubmatch(line); m != nil {
			libPath := strings.TrimSpace(m[2])
			if libPath == "" || strings.HasSuffix(libPath, "-NOTFOUND") {
				continue
			}
			entry := registry.Identify(m[1])
			if entry == nil {
				entry = registry.Identify(libPath)
			}
			if entry != nil {
				upsertComponent(seen, entry, "", filepath.Base(libPath), "cmake")
			}
		}
	}
}

func parseCMakeLists(path string, seen map[string]*inventory.Component, versions map[string]string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	for _, m := range reFindPackage.FindAllStringSubmatch(content, -1) {
		pkgName := m[1]
		if cmakeBuiltins[pkgName] {
			continue
		}
		entry := registry.Identify(pkgName)
		if entry == nil {
			entry = &registry.KnownLib{
				Name:        strings.ToLower(pkgName),
				PURLPrefix:  "pkg:generic/" + strings.ToLower(pkgName),
				Description: "Detected via CMake find_package()",
			}
		}
		upsertComponent(seen, entry, "", "", "cmake")
	}

	fetchMatches := reFetchContent.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range fetchMatches {
		pkgName := content[loc[2]:loc[3]]
		entry := registry.Identify(pkgName)
		if entry == nil {
			entry = &registry.KnownLib{
				Name:        strings.ToLower(pkgName),
				PURLPrefix:  "pkg:generic/" + strings.ToLower(pkgName),
				Description: "Detected via CMake FetchContent_Declare()",
			}
		}
		end := loc[1] + 500
		if end > len(content) {
			end = len(content)
		}
		if tm := reGitTag.FindStringSubmatch(content[loc[1]:end]); tm != nil {
			versions[strings.ToLower(pkgName)] = strings.TrimPrefix(tm[1], "v")
		}
		upsertComponent(seen, entry, "", "", "cmake")
	}

	for _, m := range reLibToken.FindAllStringSubmatch(content, -1) {
		ns := m[1]
		if cmakeBuiltins[ns] {
			continue
		}
		if entry := registry.Identify(ns); entry != nil {
			upsertComponent(seen, entry, "", "", "cmake")
		}
	}
}

func upsertComponent(seen map[string]*inventory.Component, lib *registry.KnownLib, incPath, linkLib, source string) {
	c, ok := seen[lib.Name]
	if !ok {
		c = &inventory.Component{
			Name:            lib.Name,
			Version:         "unknown",
			PURL:            lib.PURLPrefix,
			DetectionSource: source,
			Description:     lib.Description,
		}
		seen[lib.Name] = c
	}
	if incPath != "" {
		c.IncludePaths = slices.AppendUnique(c.IncludePaths, incPath)
	}
	if linkLib != "" {
		c.LinkLibraries = slices.AppendUnique(c.LinkLibraries, linkLib)
	}
}
