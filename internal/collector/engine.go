package collector

import (
	"fmt"
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

type ScanResult struct {
	Components        []*inventory.Component
	DependencyTree    *inventory.DependencyTree
	StrategiesUsed    []string
	StrategiesSkipped []string
}

type Engine struct {
	ProjectRoot string
	Verbose     bool
}

func New(projectRoot string, verbose bool) *Engine {
	return &Engine{ProjectRoot: projectRoot, Verbose: verbose}
}

func (e *Engine) Scan() (*ScanResult, error) {
	outputs := e.runDetectors()
	components, fired, quiet := e.foldOutputs(outputs)

	probers.ScanVersionHints(components, e.ProjectRoot)

	e.attachEdges(components, outputs.conanGraph)
	e.markDirectTransitive(components, outputs.conanGraph, outputs.outputs)

	tree := inventory.BuildDependencyTree(components)

	return &ScanResult{
		Components:        components,
		DependencyTree:    tree,
		StrategiesUsed:    fired,
		StrategiesSkipped: quiet,
	}, nil
}

type detectorOutput struct {
	name       string
	components []*inventory.Component
	err        error
}

type runResult struct {
	outputs     []detectorOutput
	conanGraph  *probers.ConanScanResult
}

func (e *Engine) runDetectors() runResult {
	conanDet := &probers.ConanDetector{}
	conanGraph := conanDet.ScanWithGraph(e.ProjectRoot, e.Verbose)

	others := []Detector{
		&probers.VcpkgDetector{},
		&probers.CMakeDetector{},
		&probers.CompileCommandsDetector{},
		&probers.BinariesDetector{},
		&probers.HeadersDetector{},
	}

	ch := make(chan detectorOutput, len(others)+1)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		ch <- detectorOutput{name: conanDet.Name(), components: conanGraph.Components}
	}()

	for _, d := range others {
		wg.Add(1)
		go func(det Detector) {
			defer wg.Done()
			if e.Verbose {
				fmt.Printf("[engine] Running detector: %s\n", det.Name())
			}
			comps, err := det.Scan(e.ProjectRoot, e.Verbose)
			ch <- detectorOutput{name: det.Name(), components: comps, err: err}
		}(d)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var outputs []detectorOutput
	for o := range ch {
		outputs = append(outputs, o)
	}

	return runResult{outputs: outputs, conanGraph: conanGraph}
}

func (e *Engine) foldOutputs(r runResult) (components []*inventory.Component, fired, quiet []string) {
	merged := make(map[string]*inventory.Component)

	// Process outputs in trust-level order (highest first) so that
	// "first wins" merge rules always pick the most-trusted value.
	// Secondary sort by name for full determinism.
	ordered := make([]detectorOutput, len(r.outputs))
	copy(ordered, r.outputs)
	sort.Slice(ordered, func(i, j int) bool {
		ti, tj := trustLevel(ordered[i].name), trustLevel(ordered[j].name)
		if ti != tj {
			return ti > tj
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

func (e *Engine) attachEdges(components []*inventory.Component, conanGraph *probers.ConanScanResult) {
	edges := make(map[string][]string)
	for parent, children := range conanGraph.Edges {
		pk := inventory.NormalizeKey(parent)
		for _, child := range children {
			edges[pk] = slices.AppendUnique(edges[pk], child)
		}
	}

	for _, c := range components {
		key := inventory.NormalizeKey(c.Name)
		if children, ok := edges[key]; ok {
			for _, child := range children {
				c.Dependencies = slices.AppendUnique(c.Dependencies, child)
			}
		}
	}
}

func (e *Engine) markDirectTransitive(components []*inventory.Component, conanGraph *probers.ConanScanResult, outputs []detectorOutput) {
	directNames := make(map[string]bool)
	for name := range conanGraph.DirectNames {
		directNames[inventory.NormalizeKey(name)] = true
	}

	directDetectors := map[string]bool{
		"vcpkg": true, "cmake": true, "compile_commands.json": true, "header-scan": true,
	}
	for _, o := range outputs {
		if directDetectors[o.name] {
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
	preferHigherTrust,
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

func preferHigherTrust(existing, incoming *inventory.Component) {
	if trustLevel(incoming.DetectionSource) > trustLevel(existing.DetectionSource) {
		existing.DetectionSource = incoming.DetectionSource
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

func trustLevel(source string) int {
	switch source {
	case "conan", "vcpkg":
		return 10
	case "compile_commands.json":
		return 8
	case "cmake":
		return 6
	case "binary-scan":
		return 4
	case "header-scan":
		return 1
	default:
		return 0
	}
}
