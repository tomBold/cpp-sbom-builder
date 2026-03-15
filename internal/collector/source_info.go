package collector

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
	"conan":                 {Rank: 10, Confidence: 0.97, IsDirect: false},
	"vcpkg":                 {Rank: 10, Confidence: 0.97, IsDirect: true},
	"compile_commands.json": {Rank: 8, Confidence: 0.85, IsDirect: true},
	"cmake":                 {Rank: 6, Confidence: 0.80, IsDirect: true},
	"binary-scan":           {Rank: 4, Confidence: 0.65, IsDirect: false},
	"header-scan":           {Rank: 1, Confidence: 0.60, IsDirect: true},
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
