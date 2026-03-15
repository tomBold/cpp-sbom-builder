# Fix Plan: Code Review Findings

Plan to address all issues from the code review. Ordered by priority.

---

## Phase 1: Security (Critical)

### 1.1 Path validation helper

**Goal:** Add a shared helper to validate that paths stay under project root.

**Location:** `internal/probers/helpers.go` (or new `internal/pathutil/pathutil.go`)

**Implementation:**
```go
// IsUnderRoot returns true if path (after Clean) is under root.
// Both paths should be absolute. Returns false for "/", empty, or invalid.
func IsUnderRoot(path, root string) bool {
    clean := filepath.Clean(path)
    abs, err := filepath.Abs(clean)
    if err != nil {
        return false
    }
    absRoot, err := filepath.Abs(root)
    if err != nil {
        return false
    }
    if abs == "/" || abs == "" || absRoot == "" {
        return false
    }
    rel, err := filepath.Rel(absRoot, abs)
    if err != nil {
        return false
    }
    return !strings.HasPrefix(rel, "..") && rel != ".."
}
```

**Files to create/update:**
- Add `internal/pathutil/pathutil.go` with `IsUnderRoot`
- Add `internal/pathutil/pathutil_test.go` with edge-case tests

---

### 1.2 Validate include paths in `findVersionInDir` / `findVersionInFile`

**Goal:** Never walk or read outside project root.

**Location:** `internal/probers/headers.go`

**Changes:**
- Add `projectRoot string` parameter to `findVersionInDir` and `findVersionInFile` (or pass a context struct)
- Before `os.Stat(path)` or `filepath.WalkDir(path, ...)`, call `pathutil.IsUnderRoot(path, projectRoot)`
- Reject paths like `/`, `/etc`, or any path outside project
- Update `ScanVersionHints` to pass `projectRoot`; update callers of `findVersionInDir` (currently called with `incPath` from `c.IncludePaths`)

**Note:** `ScanVersionHints` receives `projectRoot`. The include paths in `c.IncludePaths` can be absolute (from `-I`) or relative. Resolve them against project root and validate before calling `findVersionInDir`.

---

### 1.3 Fix `isInternalInclude` path validation

**Goal:** Validate candidates before `os.Stat` and ensure they stay under project root.

**Location:** `internal/probers/headers.go:126-147`

**Changes:**
- For each `candidate`, resolve to absolute path
- Call `pathutil.IsUnderRoot(candidate, projectRoot)` before `os.Stat`
- Skip candidates that escape root

---

### 1.4 Validate include paths in `compilecommands.go`

**Goal:** Only add include paths to components if they are under project root (or a whitelisted system path).

**Location:** `internal/probers/compilecommands.go` (around lines 155-170)

**Changes:**
- Before adding `incPath` to `c.IncludePaths`, resolve and validate with `pathutil.IsUnderRoot`
- Skip paths that escape root (e.g. `-I /`, `-I /usr/include` is system – may allow or reject per policy)

---

## Phase 2: Bug Fix

### 2.1 Fix `findVersionInDir` – return value in WalkDir

**Goal:** Use the result of `findVersionInFile` when walking subdirectories.

**Location:** `internal/probers/headers.go:186-195`

**Change:**
```go
_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
    if err != nil || d.IsDir() {
        return nil
    }
    lname := strings.ToLower(d.Name())
    if strings.Contains(lname, "version") || strings.Contains(lname, "config") {
        if v := findVersionInFile(p); v != "" {
            // Cannot return from WalkDir callback; use a variable
            // Store in outer scope or use sync.Once / named return
            return filepath.SkipAll  // after setting a result
        }
    }
    return nil
})
```

**Better approach:** Use a variable to capture the result and `filepath.SkipAll` to stop the walk:
```go
var foundVersion string
_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
    if err != nil || d.IsDir() {
        return nil
    }
    lname := strings.ToLower(d.Name())
    if strings.Contains(lname, "version") || strings.Contains(lname, "config") {
        if v := findVersionInFile(p); v != "" {
            foundVersion = v
            return filepath.SkipAll
        }
    }
    return nil
})
if foundVersion != "" {
    return foundVersion
}
```

---

## Phase 3: Refactoring

### 3.1 Unify `appendUnique` / `appendUniq`

**Goal:** Single implementation, used everywhere.

**Options:**
- **A:** Add `internal/slices/slices.go` with `AppendUnique(slice []string, s string) []string`
- **B:** Keep in `internal/probers/helpers.go` and have collector import probers (creates dependency)
- **C:** Add to `internal/inventory` or a neutral `internal/util` package

**Recommended:** Option A – `internal/slices/appendunique.go`

**Files to update:**
- Create `internal/slices/appendunique.go`
- Replace `appendUnique` in: `helpers.go`, `binaries.go`, `headers.go`, `compilecommands.go`, `cmake.go`, `conan.go`
- Replace `appendUniq` in: `engine.go`
- Remove `appendUnique` from `helpers.go`, `appendUniq` from `engine.go`

---

### 3.2 Unify `dedupKey` / `NormalizeKey` (optional)

**Goal:** Use one function for name normalization.

**Location:** `engine.go:191-196`, `component.go:31-36`

**Change:** Remove `dedupKey` from collector, use `inventory.NormalizeKey` everywhere. Collector already imports inventory.

---

## Phase 4: Testing

### 4.1 Unit tests for exporters

**Goal:** Test CycloneDX and SPDX exporters with synthetic `ScanResult`, not `demo/`.

**Location:** `internal/exporter/cyclonedx_test.go`, `spdx_test.go`

**Implementation:**
- Add helper `syntheticScanResult() *collector.ScanResult` that builds a minimal result (2–3 components, some deps)
- Add tests: `TestCycloneDX_WithSyntheticResult`, `TestSPDX_WithSyntheticResult`
- Keep existing integration tests that use `demo/` as optional or behind a build tag

---

### 4.2 Tests for deptree, BinariesDetector, path helpers

**Files to add/update:**
- `internal/inventory/deptree_test.go`: `TestBuildDependencyTree`, `TestBuildDependencyTree_Cycle`
- `internal/probers/detectors_test.go`: `TestBinariesDetector_Scan` (or `TestBinaries_Scan`)
- `internal/pathutil/pathutil_test.go`: `TestIsUnderRoot` with cases: under root, `..`, `/`, empty, Windows paths if needed

---

## Phase 5: Performance

### 5.1 Guard `findVersionInDir` against dangerous paths

**Goal:** Avoid walking entire filesystem when path is `/` or similar.

**Location:** `internal/probers/headers.go`

**Changes:** (Overlaps with Phase 1.2)
- Reject if `path == "/"` or `path == ""`
- Reject if path is not under project root
- Optionally limit walk depth (e.g. max 3 levels) to avoid huge trees

---

## Phase 6: Style & Maintainability

### 6.1 Fix `conan.go` variable shadowing

**Location:** `internal/probers/conan.go:152-153`

**Change:**
```go
for _, req := range node.Requires {
    reqBase := strings.SplitN(req, "#", 2)[0]
    if childName := nodeNames[reqBase]; childName != "" {
        result.DirectNames[childName] = true
    }
}
```

---

### 6.2 Logger interface (optional, lower priority)

**Goal:** Replace `fmt.Printf` with a logger for testability.

**Implementation:** Add `type Logger interface { Printf(format string, args ...any) }` and pass it to detectors. Default implementation writes to `os.Stdout`; tests can use a no-op or buffer.

---

## Phase 7: CI

### 7.1 GitHub Actions

**Goal:** Run tests and build on push/PR.

**File:** `.github/workflows/ci.yml`

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go build ./...
      - run: go test ./...
```

---

## Execution Order

| Step | Phase | Task | Est. effort |
|------|-------|------|-------------|
| 1 | 1.1 | Add `pathutil.IsUnderRoot` + tests | Small |
| 2 | 1.2–1.4 | Apply path validation in headers, compilecommands | Medium |
| 3 | 2.1 | Fix `findVersionInDir` bug | Small |
| 4 | 3.1 | Unify appendUnique/appendUniq | Small |
| 5 | 3.2 | Use NormalizeKey in collector | Trivial |
| 6 | 4.1–4.2 | Add missing tests | Medium |
| 7 | 5.1 | Guard findVersionInDir (covered by 1.2) | — |
| 8 | 6.1 | Fix conan.go shadowing | Trivial |
| 9 | 7.1 | Add GitHub Actions | Small |

---

## Dependencies Between Tasks

- Phase 1.1 must be done before 1.2, 1.3, 1.4
- Phase 2.1 can be done in parallel with Phase 1 (after 1.1)
- Phase 3.1 is independent
- Phase 4 can start after Phase 2 (bug fix) so tests validate correct behavior
