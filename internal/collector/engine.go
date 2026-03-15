package collector

import (
	"fmt"
	"path/filepath"
	"sort"
	"sync"

	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/probers"
	"github.com/tomBold/cpp-sbom-builder/internal/slices"
)

type Detector interface {
	Name() string
	Scan(projectRoot string, verbose bool) ([]*inventory.Component, error)
}

// GraphDetector extends Detector with dependency-graph data.
// The engine merges edges and direct-name sets from every
// GraphDetector into a single graph used for SBOM output.
type GraphDetector interface {
	Detector
	ScanGraph(projectRoot string, verbose bool) (
		components []*inventory.Component,
		directNames map[string]bool,
		edges map[string][]string,
	)
}

type ScanResult struct {
	ProjectName       string
	Components        []*inventory.Component
	DependencyTree    *inventory.DependencyTree
	StrategiesUsed    []string
	StrategiesSkipped []string
}

// DefaultDetectors returns the built-in detector set.
func DefaultDetectors() []Detector {
	return []Detector{
		&probers.ConanDetector{},
		&probers.VcpkgDetector{},
		&probers.CMakeDetector{},
		&probers.CompileCommandsDetector{},
		&probers.BinariesDetector{},
		&probers.HeadersDetector{},
	}
}

type Engine struct {
	ProjectRoot string
	Verbose     bool
	detectors   []Detector
}

func New(projectRoot string, verbose bool, detectors []Detector) *Engine {
	return &Engine{ProjectRoot: projectRoot, Verbose: verbose, detectors: detectors}
}

func (e *Engine) Scan() (*ScanResult, error) {
	r := e.runDetectors()
	components, fired, quiet := e.foldOutputs(r)

	probers.ScanVersionHints(components, e.ProjectRoot)

	e.attachEdges(components, r.edges)
	e.markDirectTransitive(components, r.directNames, r.outputs)

	tree := inventory.BuildDependencyTree(components)

	return &ScanResult{
		ProjectName:       filepath.Base(e.ProjectRoot),
		Components:        components,
		DependencyTree:    tree,
		StrategiesUsed:    fired,
		StrategiesSkipped: quiet,
	}, nil
}

type detectorOutput struct {
	name        string
	components  []*inventory.Component
	err         error
	directNames map[string]bool
	edges       map[string][]string
}

type runResult struct {
	outputs     []detectorOutput
	directNames map[string]bool
	edges       map[string][]string
}

// runDetectors executes all detectors concurrently, collecting results
// into a fixed-position slice keyed by registration order for determinism.
func (e *Engine) runDetectors() runResult {
	outputs := make([]detectorOutput, len(e.detectors))
	var wg sync.WaitGroup

	for i, d := range e.detectors {
		wg.Add(1)
		go func(idx int, det Detector) {
			defer wg.Done()
			if e.Verbose {
				fmt.Printf("[engine] Running detector: %s\n", det.Name())
			}
			if gd, ok := det.(GraphDetector); ok {
				comps, direct, edges := gd.ScanGraph(e.ProjectRoot, e.Verbose)
				outputs[idx] = detectorOutput{
					name: det.Name(), components: comps,
					directNames: direct, edges: edges,
				}
			} else {
				comps, err := det.Scan(e.ProjectRoot, e.Verbose)
				outputs[idx] = detectorOutput{name: det.Name(), components: comps, err: err}
			}
		}(i, d)
	}

	wg.Wait()

	mergedDirect := make(map[string]bool)
	mergedEdges := make(map[string][]string)

	for _, o := range outputs {
		for k, v := range o.directNames {
			mergedDirect[k] = v
		}
		for k, vs := range o.edges {
			mergedEdges[k] = append(mergedEdges[k], vs...)
		}
	}

	return runResult{outputs: outputs, directNames: mergedDirect, edges: mergedEdges}
}

func (e *Engine) foldOutputs(r runResult) (components []*inventory.Component, fired, quiet []string) {
	merged := make(map[string]*inventory.Component)

	ordered := make([]detectorOutput, len(r.outputs))
	copy(ordered, r.outputs)
	sort.Slice(ordered, func(i, j int) bool {
		ri, rj := sourceRank(ordered[i].name), sourceRank(ordered[j].name)
		if ri != rj {
			return ri > rj
		}
		return ordered[i].name < ordered[j].name
	})

	for _, o := range ordered {
		if o.err != nil {
			if e.Verbose {
				fmt.Printf("[engine] Detector %s error: %v\n", o.name, o.err)
			}
			quiet = append(quiet, o.name)
			continue
		}
		if len(o.components) == 0 {
			quiet = append(quiet, o.name)
			continue
		}
		fired = append(fired, o.name)
		for _, c := range o.components {
			foldInto(merged, c)
		}
	}

	return sortedComponents(merged), fired, quiet
}

func (e *Engine) attachEdges(components []*inventory.Component, edges map[string][]string) {
	normalized := make(map[string][]string)
	for parent, children := range edges {
		pk := inventory.NormalizeKey(parent)
		for _, child := range children {
			normalized[pk] = slices.AppendUnique(normalized[pk], child)
		}
	}

	for _, c := range components {
		key := inventory.NormalizeKey(c.Name)
		if children, ok := normalized[key]; ok {
			for _, child := range children {
				c.Dependencies = slices.AppendUnique(c.Dependencies, child)
			}
		}
	}
}

func (e *Engine) markDirectTransitive(components []*inventory.Component, graphDirectNames map[string]bool, outputs []detectorOutput) {
	directNames := make(map[string]bool)
	for name := range graphDirectNames {
		directNames[inventory.NormalizeKey(name)] = true
	}

	for _, o := range outputs {
		if isDirectDetector(o.name) {
			for _, c := range o.components {
				directNames[inventory.NormalizeKey(c.Name)] = true
			}
		}
	}

	referencedAsChild := make(map[string]bool)
	for _, c := range components {
		for _, childName := range c.Dependencies {
			referencedAsChild[inventory.NormalizeKey(childName)] = true
		}
	}

	for _, c := range components {
		key := inventory.NormalizeKey(c.Name)
		c.IsDirect = directNames[key] || !referencedAsChild[key]
	}
}

func sortedComponents(merged map[string]*inventory.Component) []*inventory.Component {
	out := make([]*inventory.Component, 0, len(merged))
	for _, c := range merged {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return inventory.NormalizeKey(out[i].Name) < inventory.NormalizeKey(out[j].Name)
	})
	return out
}

type mergeRule func(existing, incoming *inventory.Component)

var foldRules = []mergeRule{
	preferKnownVersion,
	preferDescription,
	accumulatePaths,
	preferRevisionChannel,
}

func foldInto(merged map[string]*inventory.Component, incoming *inventory.Component) {
	key := inventory.NormalizeKey(incoming.Name)
	existing, ok := merged[key]
	if !ok {
		merged[key] = incoming
		return
	}

	for _, rule := range foldRules {
		rule(existing, incoming)
	}
}

func preferKnownVersion(existing, incoming *inventory.Component) {
	if existing.Version == "unknown" && incoming.Version != "unknown" {
		existing.Version = incoming.Version
		existing.PURL = incoming.PURL
	}
}

func preferDescription(existing, incoming *inventory.Component) {
	if existing.Description == "" && incoming.Description != "" {
		existing.Description = incoming.Description
	}
}

func accumulatePaths(existing, incoming *inventory.Component) {
	for _, p := range incoming.IncludePaths {
		existing.IncludePaths = slices.AppendUnique(existing.IncludePaths, p)
	}
	for _, l := range incoming.LinkLibraries {
		existing.LinkLibraries = slices.AppendUnique(existing.LinkLibraries, l)
	}
}

func preferRevisionChannel(existing, incoming *inventory.Component) {
	if existing.Revision == "" && incoming.Revision != "" {
		existing.Revision = incoming.Revision
	}
	if existing.Channel == "" && incoming.Channel != "" {
		existing.Channel = incoming.Channel
	}
}
