package inventory

import "strings"

type Component struct {
	Name            string   // Canonical library name (e.g. "boost", "openssl")
	Version         string   // Detected version string, or "unknown"
	PURL            string   // Package URL (e.g. pkg:conan/boost@1.82.0)
	Revision        string   // Conan recipe revision hash (#abc123), if known
	Channel         string   // Conan user/channel (e.g. "conan/stable"), if known
	DetectionSource string   // Highest-confidence strategy that detected this
	Description     string   // Human-readable description from fingerprint DB
	IncludePaths    []string // External include paths that led to detection
	LinkLibraries   []string // Linked library names (e.g. "boost_system", "ssl")

	IsDirect     bool     // true = directly used by the project; false = transitive
	Dependencies []string // Names of child dependencies (populated by graph strategies)
}

func (c *Component) Key() string {
	return NormalizeKey(c.Name) + "@" + c.Version
}

func (c *Component) DependencyType() string {
	if c.IsDirect {
		return "direct"
	}
	return "transitive"
}

func NormalizeKey(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

func (c *Component) BOMRef() string {
	if c.PURL != "" {
		return c.PURL
	}
	ref := "pkg:generic/" + c.Name
	if c.Version != "" && c.Version != "unknown" {
		ref += "@" + c.Version
	}
	return ref
}
