# Changelog

The list of commits in this changelog is automatically generated in the release process.
The commits follow the Conventional Commit specification.

## [0.1.0] - 2025-12-02

### 🚀 Features

- Changed to new workflow for ghcr upload (#23)
- Adjust workflow files and remove local config files (#22)
- Added one more benchmarking function for signCertificate
- Created new fixed benchmark for signCertificate, updated benchmark-assert.sh
- Switched from hardcoded OS PATH in benchmark function to environment variables
- Updated code so that it automatically handle failed benchmarks
- Added continue-on-error: true for running benchmarks step
- Defined pipeline step and Taskfile command that runs all benchmark and asserts on their values
- Improved logging (#12)
- Add git-cliff for changelog generation (#13)
- Added github workflow to push to the Github package registry (#14)
- Updated Taskfile.yaml
- Updated README.MD
- Added benchmarks for sign and hash related methods
- Re-use not modified field for subject in case of use CSR (#9)
- Architecture dependent support for tools task (#6)
- Push files to crypto-broker-server repository

### 🐛 Bug Fixes

- Fixed shellcheck issues related to benchmark-assert.sh
- Removed unnecessary -count=3 flag
- Fixed error string while validating keys against profile's constraints
- Using example profiles path directly (#25)
- Improving regex in benchmark-assert.sh
- Updated bench command in pipeline
- Fixed parsing issue
- Fixed assertion script issue
- Move Profiles.yaml file to its own folder again (#10)
- Added support for custom subject strings in signCertificate. Fixed issue within Taskfile (#7)
- Updated README.md, Taskfile and .gitignore

### 💼 Other

- KSA-ADVANCED cannot be loaded
- KSA-ADVANCED cannot be loaded
- KSA-ADVANCED cannot be loaded
- Added FIPS and KSA crypto profiles
- Updated documentation regarding benchmarks

### 🚜 Refactor

- Adjust test for profile parsing
- Move profile definitions to deployment repo
- Adjust git cliff workflow (#19)

### 📚 Documentation

- Remove profile generation task in README (#16)
