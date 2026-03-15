package probers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/pathutil"
	"github.com/tomBold/cpp-sbom-builder/internal/registry"
	"github.com/tomBold/cpp-sbom-builder/internal/slices"
)

type CompileCommandsDetector struct{}

func (s *CompileCommandsDetector) Name() string { return string(DetectorCompileCommands) }

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

	WalkProject(projectRoot, nil, func(path string, d os.DirEntry) {
		if d.Name() == "compile_commands.json" {
			abs, _ := filepath.Abs(path)
			if !visited[abs] {
				discovered = append(discovered, path)
				visited[abs] = true
			}
		}
	})

	if len(discovered) == 0 {
		if verbose {
			fmt.Printf("  [%s] No compile_commands.json found\n", DetectorCompileCommands)
		}
		return nil, nil
	}

	externalIncludes := map[string]bool{}
	externalLibs := map[string]bool{}

	for _, ccPath := range discovered {
		if verbose {
			fmt.Printf("  [%s] Parsing %s\n", DetectorCompileCommands, ccPath)
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
					if pathutil.RejectPath(incPath) {
						continue
					}
					resolved := resolveIncPath(incPath, e.Directory)
					if isExternalPath(resolved, projectRoot) {
						externalIncludes[filepath.ToSlash(resolved)] = true
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
					incPath := arg[2:]
					if !pathutil.RejectPath(incPath) {
						resolved := resolveIncPath(incPath, e.Directory)
						if isExternalPath(resolved, projectRoot) {
							externalIncludes[filepath.ToSlash(resolved)] = true
						}
					}
				case strings.HasPrefix(arg, "/I") && len(arg) > 2:
					incPath := arg[2:]
					if !pathutil.RejectPath(incPath) {
						resolved := resolveIncPath(incPath, e.Directory)
						if isExternalPath(resolved, projectRoot) {
							externalIncludes[filepath.ToSlash(resolved)] = true
						}
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
			c.IncludePaths = slices.AppendUnique(c.IncludePaths, incPath)
			if v := extractVersionFromPath(incPath); v != "" && c.Version == "unknown" {
				c.Version = v
				c.PURL = lib.PURLPrefix + "@" + v
			}
		}
		if linkLib != "" {
			c.LinkLibraries = slices.AppendUnique(c.LinkLibraries, linkLib)
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
