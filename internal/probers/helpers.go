package probers

import (
	"path/filepath"
	"regexp"
	"strings"
)

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
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
