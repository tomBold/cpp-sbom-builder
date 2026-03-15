package testutil

import "github.com/tomBold/cpp-sbom-builder/internal/inventory"

// FindComponent returns the first component whose normalised name
// matches, or nil.
func FindComponent(comps []*inventory.Component, name string) *inventory.Component {
	key := inventory.NormalizeKey(name)
	for _, c := range comps {
		if inventory.NormalizeKey(c.Name) == key {
			return c
		}
	}
	return nil
}

// NameSet returns a set of component names for easy membership checks.
func NameSet(comps []*inventory.Component) map[string]bool {
	m := make(map[string]bool, len(comps))
	for _, c := range comps {
		m[c.Name] = true
	}
	return m
}
