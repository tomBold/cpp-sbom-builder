package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/tomBold/cpp-sbom-builder/internal/collector"
	"github.com/tomBold/cpp-sbom-builder/internal/exporter"
)

const toolVersion = "1.0.0"

var (
	flagDir            string
	flagOutput         string
	flagFormat         string
	flagVerbose        bool
	flagShowStrategies bool
	flagMinConfidence  float64
)

var rootCmd = &cobra.Command{
	Use:   "cpp-sbom-builder",
	Short: "C++ SBOM Generation Engine",
	Long: `cpp-sbom-builder scans a C++ project directory and produces a Software
Bill of Materials (SBOM) in CycloneDX JSON format.

It uses a layered inference engine to identify third-party dependencies:
  • Conan       — conan.lock, conanfile.txt, conanfile.py
  • vcpkg       — vcpkg.json, vcpkg-lock.json, installed/vcpkg/status
  • CMake       — CMakeCache.txt, CMakeLists.txt
  • compile_commands.json — compiler -I/-isystem include paths
  • Binaries    — .so, .a, .dll, .lib filenames
  • Header scan — #include directives (fallback)

Results from all strategies are merged, normalized, and ranked by confidence.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a C++ project and generate an SBOM",
	Long: `Scan a C++ project directory for third-party dependencies and produce
a CycloneDX 1.5 JSON SBOM.

Examples:
  cpp-sbom-builder scan --dir /path/to/project --output sbom.json
  cpp-sbom-builder scan --dir . --output - --verbose
  cpp-sbom-builder scan --dir /path/to/project --output sbom.json --show-strategies`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&flagDir, "dir", "d", ".", "Path to the C++ project root directory")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "sbom.json", "Output file path (use '-' for stdout)")
	scanCmd.Flags().StringVarP(&flagFormat, "format", "f", "cyclonedx", "Output format: cyclonedx, spdx")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().BoolVar(&flagShowStrategies, "show-strategies", false, "Print which strategies fired after scanning")
	scanCmd.Flags().Float64Var(&flagMinConfidence, "min-confidence", 0.0,
		"Minimum confidence threshold for emitting a component (0.0–1.0, default 0 = emit all)")

	rootCmd.AddCommand(scanCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(flagDir)
	if err != nil {
		return fmt.Errorf("cannot resolve directory %q: %w", flagDir, err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return fmt.Errorf("directory %q does not exist: %w", absDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", absDir)
	}

	statusOut := os.Stderr
	if flagOutput != "-" {
		statusOut = os.Stdout
	}

	fmt.Fprintf(statusOut, "cpp-sbom-builder v%s\n", toolVersion)
	fmt.Fprintf(statusOut, "Scanning: %s\n", absDir)

	s := collector.New(absDir, flagVerbose)
	result, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	fmt.Fprintf(statusOut, "Found %d component(s)\n", len(result.Components))

	if flagShowStrategies || flagVerbose {
		if len(result.StrategiesUsed) > 0 {
			fmt.Fprintf(statusOut, "Strategies that found results: %v\n", result.StrategiesUsed)
		}
		if len(result.StrategiesSkipped) > 0 {
			fmt.Fprintf(statusOut, "Strategies with no results:    %v\n", result.StrategiesSkipped)
		}
	}

	switch flagFormat {
	case "cyclonedx", "cdx":
		if err := exporter.WriteCycloneDX(result, flagOutput, toolVersion, flagMinConfidence); err != nil {
			return fmt.Errorf("failed to write CycloneDX output: %w", err)
		}
	case "spdx":
		if err := exporter.WriteSPDX(result, flagOutput, toolVersion, flagMinConfidence); err != nil {
			return fmt.Errorf("failed to write SPDX output: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format %q (supported: cyclonedx, spdx)", flagFormat)
	}

	if flagOutput != "-" {
		fmt.Fprintf(statusOut, "SBOM written to: %s\n", flagOutput)
	}

	return nil
}
