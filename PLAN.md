# cpp-sbom-builder — Architecture Plan

## Problem Statement

C++ has no universal package manager. A project may use Conan, vcpkg, CMake FetchContent, hand-vendored headers, or any combination of these. An SBOM engine must handle all of them.

The tool scans a project **after build** (so compiler artifacts are available) and produces a component inventory in CycloneDX 1.5 JSON.

---

## Architecture Overview

```
main.go
  └─ cmd/root.go          (cobra CLI: scan command + flags)
        └─ scanner.Scan()  (orchestrator)
              ├─ ConanStrategy         → conan.lock, conanfile.txt, conanfile.py
              ├─ VcpkgStrategy         → vcpkg.json, vcpkg-lock.json, status
              ├─ CMakeStrategy         → CMakeCache.txt, CMakeLists.txt
              ├─ CompileCommandsStrategy → compile_commands.json
              ├─ BinariesStrategy      → *.so, *.a, *.dll, *.lib, *.dylib
              └─ HeadersStrategy       → *.cpp, *.h, *.hpp, ...
                    ↓ all run concurrently ↓
              merge + normalize + deduplicate
                    ↓
              ScanVersionHints()       (post-process: fill in unknown versions)
              BuildDependencyTree()    (mark direct vs transitive)
                    ↓
              output.WriteCycloneDX() → sbom.json
```

---

## Key Data Structures

```go
// model.Component — the canonical representation of a detected dependency
type Component struct {
    Name            string   // Canonical library name (e.g. "boost")
    Version         string   // Detected version or "unknown"
    PURL            string   // Package URL (pkg:conan/boost@1.82.0)
    Revision        string   // Conan recipe revision hash
    Channel         string   // Conan user/channel
    DetectionSource string   // Winning strategy name
    Description     string   // From fingerprint DB
    IncludePaths    []string // External include paths that matched
    LinkLibraries   []string // Linked library names
    IsDirect        bool     // Direct vs transitive
    Dependencies    []string // Child dependency names (from conan.lock graph)
}
```

---

## Detection Strategy Design

### Why Multiple Strategies?

C++ projects have no single authoritative source of truth:
- A project using Conan + vcpkg simultaneously is common
- `compile_commands.json` reveals what the compiler actually compiled against (ground truth, but requires a build)
- Header scanning catches dependencies not declared in any manifest (vendored, git-submodule, system-installed)

Each strategy provides a different signal; their combination maximises recall with controlled precision.

### Confidence Model

Each strategy is assigned a confidence score:

| Strategy | Confidence | Rationale |
|---|---|---|
| conan / vcpkg | 0.97 | Authoritative manifest — exact names and versions |
| compile_commands.json | 0.85 | Compiler-level truth — what was actually compiled against |
| cmake | 0.80 | Build system declaration — correct but not always versioned |
| binary-scan | 0.65 | Filename inference — could match internal libs |
| header-scan | 0.60 | Heuristic — filtered but inherently approximate |

When multiple strategies detect the same library, the higher-confidence source's version wins. All evidence (include paths, link libraries) is accumulated.

### Normalization and Deduplication

Libraries from different strategies may have different names:
- Conan: `nlohmann_json`, vcpkg: `nlohmann-json`, fingerprint: `nlohmann-json`
- Conan: `openssl`, CMake: `OpenSSL`, header: `openssl`

The scanner normalizes names with `normalizeKey()` (lowercase, `_`/`.` → `-`) before merging. Strategies that match a known fingerprint use the canonical fingerprint name.

---

## Version Resolution

Version is set by the first strategy (by confidence rank) that provides one:

1. **Conan / vcpkg manifest** — authoritative version string
2. **CMake FetchContent GIT_TAG** — version tag from CMakeLists.txt
3. **compile_commands.json path** — extracted from include path (e.g. `boost_1_82_0` → `1.82.0`)
4. **Binary filename** — `libssl.so.3.1.4` → `3.1.4`
5. **Header version macro** — `#define BOOST_LIB_VERSION "1_82"` scanned post-detection

---

## Dependency Tree

The `conan.lock` v1 graph format contains explicit direct/transitive edges (node 0 = project root, edges list direct requirements). These are used to build the `dependencies[]` section of the CycloneDX output.

Without a conan.lock graph, all detected components are marked as direct (conservative). A full dependency tree reconstruction from CMake or vcpkg would require running those tools, which is out of scope for this MVP.

---

## False Positive Mitigation

1. **Stdlib deny-list**: ~80 C/C++ standard library headers are filtered before fingerprint matching
2. **Internal header resolution**: include paths that resolve to a file inside the project root are skipped
3. **Fingerprint-gated matching**: unknown includes (not in the fingerprint DB) are silently dropped rather than creating low-quality entries
4. **Confidence threshold**: `--min-confidence 0.80` skips header-scan and binary-scan results

---

## Performance Design

- **Streaming I/O**: `bufio.Scanner` line-by-line reads; no full-file buffering except for JSON manifests
- **Compiled regexes**: all patterns are compiled once at startup (`regexp.MustCompile` at package level)
- **Directory skipping**: `.git`, `node_modules`, `CMakeFiles`, `build`, `out`, `_build`, `bazel-*`, `vendor`, `third_party` are skipped entirely
- **Concurrent strategies**: all strategies run in parallel goroutines; I/O wait time is hidden behind concurrency
- **No AST parsing**: string-based matching is 10–100× faster than C++ AST parsing for this use case

---

## What the MVP Intentionally Omits

| Feature | Rationale for deferral |
|---|---|
| ELF SONAME parsing | Requires binary parsing; filename inference covers most cases |
| pkg-config (.pc files) | Niche; most projects using pkg-config also have CMake |
| Meson support | Low market share vs. CMake+Conan; addable as a new Strategy |
| SPDX output | CycloneDX is more widely adopted for SCA use cases |
| Vulnerability lookup | Not required by the assignment |
| Windows PE/MSVC .pdb analysis | Complex; MSVC users typically have vcpkg or CMake manifests |

---

## Sample Project Design

`sample/` is **intentionally synthetic**. It includes:
- `conanfile.txt` — Conan manifest (boost, openssl, nlohmann-json, spdlog)
- `vcpkg.json` — vcpkg manifest (zlib, libcurl, sqlite3, yaml-cpp)
- `CMakeLists.txt` — CMake declarations (fmt via FetchContent, openssl/boost via find_package)
- `compile_commands.json` — pre-generated compiler DB (abseil, grpc via external -I paths)
- `src/main.cpp`, `src/http_client.cpp` — source with third-party `#include` directives
- `build/libssl.so.3.1.4`, `build/libz.so.1.2.13` — binary stubs for artifact detection

This gives the reviewer a deterministic, reproducible demonstration of all six strategies without requiring a real C++ toolchain.
