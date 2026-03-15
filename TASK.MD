Take-Home Assignment: C++ SBOM
Generation Engine

1. Overview
   The goal of this task is to build a core component of a Software Bill of Materials (SBOM)
   generation product specifically for C++. Unlike languages with universal package managers
   (like npm or pip), C++ dependency management is fragmented.
   Your task is to build an SBOM Inference Engine that scans a project's build outputs,
   filesystem and configuration files directly to detect third-party dependencies.
2. The Task
   Create a CLI application (preferably in Go, Rust is also allowed) named cpp-sbom-builder.
   User Flow: User points the tool at a C++ project root directory after build -> Tool scans files
   recursively -> Receives a standard SBOM JSON.

- Vulnerability results are not required as part of the tasks
  When the tool is executed against a target directory, it should:

1. Analyze the build outputs for dependencies: Run a set of strategies to build the
   dependency tree (examples: source code, binary artifacts, configuration files etc.)
2. Generate output: Produce a valid JSON file in either SPDX or CycloneDX format listing
   the detected components.
3. Guiding Questions
   Be prepared to discuss these in the review:
   ● False Positives and inaccuracies: How do you distinguish between standard library
   headers (e.g., <vector>), internal project headers, and third-party library headers without
   a compiler? What other inaccuracies may exist?
   ● Version Detection: If a dependency is detected via header files only (no manifest
   found), how might you attempt to detect the version of that library?
   ● Performance: How would this architecture perform when scanning a monorepo with 10
   GB of source code? Would you use regular expressions, string searching, or an AST
   parser?
4. Setup for the Reviewer
   When you submit, please provide a GitHub repository that contains:
   ● Source Code for the cpp-sbom-builder.

● Sample Project to run on (recommended to use an open source project)
● README.md with instructions on how to:
○ Run the project in a local environment.
○ Execute the tool against the provided sample data.
○ (Optional) Run a test suite to verify the output format.
