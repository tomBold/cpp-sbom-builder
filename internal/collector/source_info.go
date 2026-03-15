package collector

import (
	"github.com/tomBold/cpp-sbom-builder/internal/inventory"
	"github.com/tomBold/cpp-sbom-builder/internal/probers"
)

// sourceInfo describes a single detector's position in the
// source-priority model.  All per-detector policy lives here;
// add new detectors by extending sourceRegistry.
type sourceInfo struct {
	Rank       int     // merge sort order — higher values are processed first
	Confidence float64 // [0,1] confidence exported into SBOM metadata / filtering
	IsDirect   bool    // true → components count as direct dependencies
}

// sourceRegistry is the single source of truth for detector priority,
// confidence, and dependency classification.
//
// Merge strategy: detectors are sorted by Rank descending before
// folding, so "first non-empty wins" rules always pick the most
// trusted value without needing per-rule trust checks.
var sourceRegistry = map[string]sourceInfo{
	string(probers.DetectorConan):           {Rank: 10, Confidence: 0.97, IsDirect: false},
	string(probers.DetectorVcpkg):           {Rank: 10, Confidence: 0.97, IsDirect: true},
	string(probers.DetectorCompileCommands): {Rank: 8, Confidence: 0.85, IsDirect: true},
	string(probers.DetectorCMake):           {Rank: 6, Confidence: 0.80, IsDirect: true},
	string(probers.DetectorBinaryScan):      {Rank: 4, Confidence: 0.65, IsDirect: false},
	string(probers.DetectorHeaderScan):      {Rank: 1, Confidence: 0.60, IsDirect: true},
}

func sourceRank(name string) int {
	return sourceRegistry[name].Rank
}

// SourceConfidence returns the [0,1] confidence score for a detection
// source.  Unknown sources default to 0.50.
func SourceConfidence(name string) float64 {
	if info, ok := sourceRegistry[name]; ok {
		return info.Confidence
	}
	return 0.50
}

func isDirectDetector(name string) bool {
	return sourceRegistry[name].IsDirect
}

// FilterByConfidence returns components whose detection source meets the
// minimum confidence threshold. A threshold of 0 disables filtering.
func FilterByConfidence(components []*inventory.Component, minConfidence float64) []*inventory.Component {
	if minConfidence <= 0 {
		out := make([]*inventory.Component, len(components))
		copy(out, components)
		return out
	}
	var out []*inventory.Component
	for _, c := range components {
		if SourceConfidence(c.DetectionSource) >= minConfidence {
			out = append(out, c)
		}
	}
	return out
}
