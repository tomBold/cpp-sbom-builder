# cpp-sbom-builder

A **Software Bill of Materials (SBOM) generation engine** for C++ projects. Scans your project folder and produces a valid **CycloneDX 1.5** or **SPDX 2.3** JSON file listing all detected third-party dependencies.

---

## Flow (How It Works)

```text
┌─────────────────────────────────────────────────────────────────┐
│  YOU                                                             │
│  Run: cpp-sbom-builder scan --dir ./my-project --output sbom-cyclonedx.json│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: Scan                                                    │
│  Tool walks your project folder and runs 6 detectors in parallel │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │  Conan   │ │  vcpkg   │ │  CMake   │ │ compile_commands  │   │
│  │ (lock,   │ │ (json,   │ │(Lists,   │ │ (-I include paths)│   │
│  │  txt)    │ │  lock)   │ │ Cache)   │ │                  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
│  ┌──────────┐ ┌──────────┐                                       │
│  │ Binaries │ │ Headers  │                                       │
│  │(.so,.dll)│ │(#include)│                                       │
│  └──────────┘ └──────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: Deduplicate & Enrich                                    │
│  One component per library. We combine evidence from all          │
│  detectors; when versions conflict, manifests beat compiler     │
│  artifacts beat binary filenames beat header inference.           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: Output                                                  │
│  CycloneDX 1.5 or SPDX 2.3 JSON with components, dependencies,  │
│  name, version, purl, detectionSource, etc.                      │
└─────────────────────────────────────────────────────────────────┘
```

**In one sentence:** Point the tool at a folder → it scans config files, binaries, and source → merges everything → writes an SBOM JSON.

---

## Quick Start

```bash
git clone https://github.com/tomBold/cpp-sbom-builder.git
cd cpp-sbom-builder
```

**Option A — run without building:**

```bash
go run . scan --dir ./demo --verbose
```

**Option B — build then run:**

```bash
go build -o cpp-sbom-builder .
./cpp-sbom-builder scan --dir ./demo --verbose          # Linux/macOS
.\cpp-sbom-builder.exe scan --dir .\demo --verbose      # Windows
```

Output is written to the `output/` folder with a timestamped filename (e.g. `output/sbom-cyclonedx-2026-03-15_14-30-21.json`) by default. The folder is created automatically. Use `--output <path>` to write to a specific path instead.

**Need:** Go 1.22+. No compiler, CMake, or Conan required.

---

## Run Against Sample Project

The `demo/` folder is a synthetic C++ project that triggers every detector:

```bash
go run . scan --dir ./demo --verbose --show-strategies
```

(Or `.\cpp-sbom-builder.exe scan ...` on Windows after building.)

To generate SPDX instead of CycloneDX:

```bash
go run . scan --dir ./demo --format spdx --verbose
```

## Run Against Your Project

Point at your project root (after build, so `compile_commands.json` exists if you use CMake):

```bash
go run . scan --dir /path/to/your/project
```

**Flags:**

| Flag | Description | Default |
| --- | --- | --- |
| `--dir` | Folder to scan | (required) |
| `--output` | Output file path, or `-` for stdout | auto-timestamped |
| `--format` | `cyclonedx` or `spdx` | `cyclonedx` |
| `--verbose` | Print what each detector finds | `false` |
| `--show-strategies` | List detection strategies used | `false` |
| `--min-confidence` | Only include components ≥ this score (0–1) | `0` |

---

## Detectors (What We Look At)

| Detector | What it reads | Confidence |
| --- | --- | --- |
| Conan | `conan.lock`, `conanfile.txt`, `conanfile.py` | 0.97 |
| vcpkg | `vcpkg.json`, `vcpkg-lock.json`, `installed/vcpkg/status` | 0.97 |
| CMake | `CMakeLists.txt`, `CMakeCache.txt` | 0.80 |
| compile_commands | `compile_commands.json` (compiler -I paths) | 0.85 |
| Binary scan | `.so`, `.a`, `.dll`, `.lib` filenames | 0.65 |
| Header scan | `#include` in `.cpp`/`.h` (fallback) | 0.60 |

---

## Output Format

When `--output` is omitted, the tool writes a timestamped file into the `output/` folder so repeated runs never overwrite previous results:

| Format | Flag | Example output file |
| --- | --- | --- |
| **CycloneDX 1.5** | `--format cyclonedx` (default) | `output/sbom-cyclonedx-2026-03-15_14-30-21.json` |
| **SPDX 2.3** | `--format spdx` | `output/sbom-spdx-2026-03-15_14-30-21.json` |

```bash
go run . scan --dir ./demo                    # CycloneDX → output/sbom-cyclonedx-*.json
go run . scan --dir ./demo --format spdx     # SPDX → output/sbom-spdx-*.json
go run . scan --dir ./demo --output sbom.json # specific path
go run . scan --dir ./demo --output -        # JSON to stdout
```

---

## Architecture

The scan engine uses **dependency injection** for detectors. Every detector satisfies a `Detector` interface; detectors that also provide a dependency graph satisfy `GraphDetector`:

```go
type Detector interface {
    Name() string
    Scan(projectRoot string, verbose bool) []*inventory.Component
}

type GraphDetector interface {
    Detector
    ScanGraph(projectRoot string, verbose bool) ([]*inventory.Component, map[string]bool, map[string][]string)
}
```

`collector.New()` accepts a `[]Detector` slice, making it easy to swap, add, or mock detectors in tests:

```go
engine := collector.New(projectRoot, verbose, collector.DefaultDetectors())
```

All 6 detectors run in parallel. Results are deduplicated, merged by confidence ranking, and enriched with dependency-graph edges (direct vs. transitive) from `GraphDetector` implementations.

---

## Tests

```bash
go test ./...
```

Unit tests for probers, collector, registry, and inventory; integration tests for SBOM output. The collector tests include fake detectors injected via the `Detector` interface to verify the engine independently of real file parsing.

---

## Guiding Questions (Task Review Answers)

### 1. False Positives — How do you tell stdlib, internal, and third-party headers apart (without a compiler)?

| Type | How we filter |
| --- | --- |
| **Stdlib** (`&lt;vector&gt;`, `&lt;iostream&gt;`) | Deny-list of ~80 C/C++ header names. We never report these. |
| **Internal** (your own headers) | If the include path points to a file inside the project (`include/`, `src/`, `lib/`) → skip. Quoted `"foo.h"` → skip. |
| **Third-party** (`&lt;boost/...&gt;`, `&lt;openssl/...&gt;`) | Only angle-bracket includes that match our library catalog are reported. |

**Other inaccuracies:** Libraries not in the catalog are dropped. Binary scanner only looks at filenames. CMake variables like `${DEPS}` are not expanded. `compile_commands.json` may miss generated files. Commented-out lines in `conanfile.py` and `CMakeLists.txt` are stripped before parsing to prevent false positives.

---

### 2. Version Detection — If we only see header files (no manifest), how do we get the version?

1. **Path** — Include path often has the version (e.g. `/opt/zlib-1.2.13/include`). We extract it with a regex.
2. **Version macros** — We scan `version.h`, `config.h` for `#define FOO_VERSION "1.2.3"`.
3. **Binary filename** — Shared libs like `libssl.so.3.1.4` have the version in the name. We parse it.

We try all three; the first one that works wins.

---

### 3. Performance — 10 GB monorepo: regex, string search, or AST?

**We use regex and string search, not an AST.**

- **Why:** We only need to find `#include` lines. We don't need to understand the rest of the code. An AST would parse the full C++ grammar (templates, macros, etc.) — that's heavy and slow. Pattern matching is enough and much faster.
- **Speedups:** Skip `.git`, `build`, `vendor`, `node_modules`. Run all 6 detectors in parallel. Manifest detectors only read a few small files.
- **Scale:** A 10 GB monorepo with ~500k source files should finish in a few seconds. If slow, use `--min-confidence 0.80` to skip the header scan.
