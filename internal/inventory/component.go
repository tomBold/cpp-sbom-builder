package inventory

import "strings"

type Component struct {
	Name            string
	Version         string
	PURL            string
	Revision        string // Conan recipe revision hash, if known
	Channel         string // Conan user/channel, if known
	DetectionSource string
	Description     string
	IncludePaths    []string
	LinkLibraries   []string

	IsDirect     bool
	Dependencies []string
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
