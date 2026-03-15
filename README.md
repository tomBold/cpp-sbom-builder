# cpp-sbom-builder

A **Software Bill of Materials (SBOM) generation engine** for C++ projects. Scans your project folder and produces a valid **CycloneDX 1.5 JSON** file listing all detected third-party dependencies.

---

## Flow (How It Works)

```text
┌─────────────────────────────────────────────────────────────────┐
│  YOU                                                             │
│  Run: cpp-sbom-builder scan --dir ./my-project --output sbom.json│
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
│  sbom.json — CycloneDX 1.5 JSON with components[] and            │
│  dependencies[] (name, version, purl, detectionSource, etc.)     │
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
go run . scan --dir ./demo --output sbom.json --verbose
```

**Option B — build then run:**

```bash
go build -o cpp-sbom-builder .
./cpp-sbom-builder scan --dir ./demo --output sbom.json --verbose   # Linux/macOS
.\cpp-sbom-builder.exe scan --dir .\demo --output sbom.json --verbose   # Windows
```

**Need:** Go 1.22+. No compiler, CMake, or Conan required.

---

## Run Against Sample Project

The `demo/` folder is a fake C++ project that triggers every detector:

```bash
go run . scan --dir ./demo --output sbom.json --verbose --show-strategies
```

(Or `.\cpp-sbom-builder.exe scan ...` on Windows after building.)

## Run Against Your Project

Point at your project root (after build, so `compile_commands.json` exists if you use CMake):

```bash
go run . scan --dir /path/to/your/project --output sbom.json
```

**Flags:** `--dir` (folder to scan), `--output` (file or `-` for stdout), `--format` (`cyclonedx` or `spdx`), `--verbose`, `--show-strategies`, `--min-confidence` (0–1).

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

Default output: `sbom.json` (CycloneDX). Use `--output` to change path; use `-` for stdout.

| Format | Flag | Typical output file |
| --- | --- | --- |
| **CycloneDX 1.5** | `--format cyclonedx` (default) | `sbom.json` |
| **SPDX 2.3** | `--format spdx` | `sbom-spdx.json` |

```bash
go run . scan --dir ./demo --output sbom.json                    # CycloneDX (default)
go run . scan --dir ./demo --output sbom-spdx.json --format spdx  # SPDX
go run . scan --dir ./demo --output -                             # JSON to stdout
```

---

## Tests

```bash
go test ./...
```

Unit tests for probers, collector, registry, inventory; integration tests for SBOM output.

---

## Guiding Questions (Task Review Answers)

### 1. False Positives — How do you tell stdlib, internal, and third-party headers apart (without a compiler)?

| Type | How we filter |
| --- | --- |
| **Stdlib** (`&lt;vector&gt;`, `&lt;iostream&gt;`) | Deny-list of ~80 C/C++ header names. We never report these. |
| **Internal** (your own headers) | If the include path points to a file inside the project (`include/`, `src/`, `lib/`) → skip. Quoted `"foo.h"` → skip. |
| **Third-party** (`&lt;boost/...&gt;`, `&lt;openssl/...&gt;`) | Only angle-bracket includes that match our library catalog are reported. |

**Other inaccuracies:** Libraries not in the catalog are dropped. Binary scanner only looks at filenames. CMake variables like `${DEPS}` are not expanded. `compile_commands.json` may miss generated files.

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
