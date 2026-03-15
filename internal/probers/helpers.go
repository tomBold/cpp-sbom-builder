package probers

import (
	"path/filepath"
	"regexp"
	"strings"
)

// resolveIncPath resolves path against baseDir when path is relative and
// baseDir is non-empty.  This is needed for compile_commands.json where each
// entry has a "directory" field that serves as the working directory for the
// compilation command; relative include paths like -I../third_party must be
// resolved against that directory, not the process CWD.
func resolveIncPath(path, baseDir string) string {
	if path == "" || filepath.IsAbs(path) || baseDir == "" {
		return path
	}
	return filepath.Join(baseDir, path)
}

func isExternalPath(path, projectRoot string) bool {
	if path == "" {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return !strings.HasPrefix(path, ".") && filepath.IsAbs(path)
	}
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return false
	}
	absPath = filepath.ToSlash(strings.ToLower(absPath))
	absRoot = filepath.ToSlash(strings.ToLower(absRoot))
	return !strings.HasPrefix(absPath, absRoot)
}

var reVersionInPath = regexp.MustCompile(`[-_](\d+)[._](\d+)(?:[._](\d+))?`)

func extractVersionFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if m := reVersionInPath.FindStringSubmatch(part); m != nil {
			v := m[1] + "." + m[2]
			if m[3] != "" {
				v += "." + m[3]
			}
			return v
		}
	}
	return ""
}

var reVersionInLibName = regexp.MustCompile(`[-_](\d+)[._](\d+)(?:[._](\d+))?(?:\.lib|\.a)?$`)

func extractVersionFromLibName(lib string) string {
	if m := reVersionInLibName.FindStringSubmatch(lib); m != nil {
		v := m[1] + "." + m[2]
		if m[3] != "" {
			v += "." + m[3]
		}
		return v
	}
	return ""
}
