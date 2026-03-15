package probers

// DetectorName is a typed identifier for a detection strategy,
// replacing stringly-typed names throughout the codebase.
type DetectorName string

const (
	DetectorConan           DetectorName = "conan"
	DetectorVcpkg           DetectorName = "vcpkg"
	DetectorCMake           DetectorName = "cmake"
	DetectorCompileCommands DetectorName = "compile_commands.json"
	DetectorBinaryScan      DetectorName = "binary-scan"
	DetectorHeaderScan      DetectorName = "header-scan"
)
