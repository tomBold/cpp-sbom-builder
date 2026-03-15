package inventory

import "sort"

type TreeNode struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	PURL            string      `json:"purl,omitempty"`
	DependencyType  string      `json:"dependencyType"` // "direct" or "transitive"
	DetectionSource string      `json:"detectionSource,omitempty"`
	Description     string      `json:"description,omitempty"`
	Children        []*TreeNode `json:"children,omitempty"`
}

type DependencyTree struct {
	Direct     []*Component
	Transitive []*Component
	All        []*Component
	ByName     map[string]*Component
	Roots      []*TreeNode
}

func BuildDependencyTree(components []*Component) *DependencyTree {
	tree := &DependencyTree{
		ByName: make(map[string]*Component, len(components)),
	}
	for _, c := range components {
		tree.All = append(tree.All, c)
		tree.ByName[NormalizeKey(c.Name)] = c
		tree.ByName[c.Name] = c
		if c.IsDirect {
			tree.Direct = append(tree.Direct, c)
		} else {
			tree.Transitive = append(tree.Transitive, c)
		}
	}
	tree.Roots = tree.buildRoots()
	return tree
}

type workItem struct {
	comp      *Component
	node      *TreeNode
	ancestors map[string]bool
}

func (t *DependencyTree) buildRoots() []*TreeNode {
	directs := make([]*Component, len(t.Direct))
	copy(directs, t.Direct)
	sort.Slice(directs, func(i, j int) bool { return directs[i].Name < directs[j].Name })

	var roots []*TreeNode
	queue := make([]workItem, 0, len(directs))

	for _, c := range directs {
		node := componentToNode(c, "direct")
		roots = append(roots, node)
		queue = append(queue, workItem{
			comp:      c,
			node:      node,
			ancestors: map[string]bool{c.Key(): true},
		})
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		childNames := make([]string, len(item.comp.Dependencies))
		copy(childNames, item.comp.Dependencies)
		sort.Strings(childNames)

		for _, childName := range childNames {
			childComp := t.ByName[NormalizeKey(childName)]
			if childComp == nil {
				item.node.Children = append(item.node.Children, &TreeNode{
					Name:           childName,
					Version:        "unknown",
					PURL:           "pkg:generic/" + childName,
					DependencyType: "transitive",
				})
				continue
			}
			depType := "transitive"
			if childComp.IsDirect {
				depType = "direct"
			}
			childNode := componentToNode(childComp, depType)
			item.node.Children = append(item.node.Children, childNode)

			if item.ancestors[childComp.Key()] {
				continue // cycle — emit as leaf
			}
			childAncestors := make(map[string]bool, len(item.ancestors)+1)
			for k := range item.ancestors {
				childAncestors[k] = true
			}
			childAncestors[childComp.Key()] = true
			queue = append(queue, workItem{comp: childComp, node: childNode, ancestors: childAncestors})
		}
	}
	return roots
}

func componentToNode(c *Component, depType string) *TreeNode {
	return &TreeNode{
		Name:            c.Name,
		Version:         c.Version,
		PURL:            c.PURL,
		DependencyType:  depType,
		DetectionSource: c.DetectionSource,
		Description:     c.Description,
	}
}
