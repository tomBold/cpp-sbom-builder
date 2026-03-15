package probers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/registry"
)

type CompileCommandsDetector struct{}

func (s *CompileCommandsDetector) Name() string { return "compile_commands.json" }

type ccEntry struct {
	Directory string   `json:"directory"`
	Command   string   `json:"command"`
	Arguments []string `json:"arguments"`
	File      string   `json:"file"`
}

var (
	reIncPath    = regexp.MustCompile(`(?i)(?:^|[\s,])(?:-I|/I|-isystem\s+|-imsvc\s*)([^\s,]+)`)
	reLinkerFlag = regexp.MustCompile(`(?i)(?:^|[\s,])(?:-l([^\s,]+)|/DEFAULTLIB:([^\s,]+))`)
)

func (s *CompileCommandsDetector) Scan(projectRoot string, verbose bool) ([]*inventory.Component, error) {
	candidates := []string{
		filepath.Join(projectRoot, "compile_commands.json"),
		filepath.Join(projectRoot, "build", "compile_commands.json"),
		filepath.Join(projectRoot, "out", "compile_commands.json"),
		filepath.Join(projectRoot, "cmake-build-debug", "compile_commands.json"),
		filepath.Join(projectRoot, "cmake-build-release", "compile_commands.json"),
		filepath.Join(projectRoot, ".build", "compile_commands.json"),
	}

	discovered := []string{}
	visited := map[string]bool{}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			if !visited[abs] {
				discovered = append(discovered, c)
				visited[abs] = true
			}
		}
	}

	_ = filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
		}
		if !d.IsDir() && d.Name() == "compile_commands.json" {
			abs, _ := filepath.Abs(path)
			if !visited[abs] {
				discovered = append(discovered, path)
				visited[abs] = true
			}
		}
		return nil
	})

	if len(discovered) == 0 {
		if verbose {
			fmt.Println("  [compile_commands] No compile_commands.json found")
		}
		return nil, nil
	}

	externalIncludes := map[string]bool{}
	externalLibs := map[string]bool{}

	for _, ccPath := range discovered {
		if verbose {
			fmt.Printf("  [compile_commands] Parsing %s\n", ccPath)
		}
		data, err := os.ReadFile(ccPath)
		if err != nil {
			continue
		}
		var entries []ccEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			continue
		}

		for _, e := range entries {
			cmdStr := e.Command
			if cmdStr == "" && len(e.Arguments) > 0 {
				cmdStr = strings.Join(e.Arguments, " ")
			}

			for _, m := range reIncPath.FindAllStringSubmatch(cmdStr, -1) {
				if len(m) > 1 {
					incPath := strings.TrimSpace(m[1])
					if isExternalPath(incPath, projectRoot) {
						externalIncludes[filepath.ToSlash(incPath)] = true
					}
				}
			}

			for _, m := range reLinkerFlag.FindAllStringSubmatch(cmdStr, -1) {
				lib := ""
				if len(m) > 1 && m[1] != "" {
					lib = m[1]
				} else if len(m) > 2 && m[2] != "" {
					lib = m[2]
				}
				if lib != "" {
					externalLibs[lib] = true
				}
			}

			for _, arg := range e.Arguments {
				arg = strings.TrimSpace(arg)
				switch {
				case strings.HasPrefix(arg, "-I") && len(arg) > 2:
					if isExternalPath(arg[2:], projectRoot) {
						externalIncludes[filepath.ToSlash(arg[2:])] = true
					}
				case strings.HasPrefix(arg, "/I") && len(arg) > 2:
					if isExternalPath(arg[2:], projectRoot) {
						externalIncludes[filepath.ToSlash(arg[2:])] = true
					}
				case strings.HasPrefix(arg, "-l") && len(arg) > 2:
					externalLibs[arg[2:]] = true
				}
			}
		}
	}

	return resolveComponents(externalIncludes, externalLibs, s.Name()), nil
}

func resolveComponents(includes map[string]bool, libs map[string]bool, source string) []*inventory.Component {
	seen := map[string]*inventory.Component{}

	record := func(lib *registry.KnownLib, incPath, linkLib string) {
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
			c.IncludePaths = appendUnique(c.IncludePaths, incPath)
			if v := extractVersionFromPath(incPath); v != "" && c.Version == "unknown" {
				c.Version = v
				c.PURL = lib.PURLPrefix + "@" + v
			}
		}
		if linkLib != "" {
			c.LinkLibraries = appendUnique(c.LinkLibraries, linkLib)
			if v := extractVersionFromLibName(linkLib); v != "" && c.Version == "unknown" {
				c.Version = v
				c.PURL = lib.PURLPrefix + "@" + v
			}
		}
	}

	for incPath := range includes {
		if lib := registry.Identify(incPath); lib != nil {
			record(lib, incPath, "")
		}
	}
	for linkLib := range libs {
		if lib := registry.Identify(linkLib); lib != nil {
			record(lib, "", linkLib)
		}
	}

	result := make([]*inventory.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result
}
