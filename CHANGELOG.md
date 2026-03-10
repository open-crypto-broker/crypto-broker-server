# Changelog

The list of commits in this changelog is automatically generated in the release process.
The commits follow the Conventional Commit specification.

## [0.2.0] - 2026-03-09

### 🚀 Features

- Add SBOM generation and OCM component generation (#56)
- Changed socket path
- Implemented ability to get env variables from .env file for Taskfile
- Added ability to work with FIPS mode through Taskfile
- Implemented metrics in server
- Updated benchmarks
- Updated workflow
- Updated benchmarks, added new benchmark, updated assert-benchmark script
- Add Subject Key Identifier (SKI) extension to certificate signing (#49)
- Linted code
- Updated OTEL logging by adding ability to send them using OTLP & gRPC
- Introduced OTEL constants, updated Taskfile, updated tracer
- Add otlphttp exporter for dynatrace
- Updated Taskfile by adding OTEL related vars and using it in run command
- Updated protobuf reference, regenerated code, implemented fake endpoint logic
- Added health check for docker (#40)
- Removed unecessary comments
- Updated submodule reference
- Updated code
- Switched to explicit tracing
- Implemented OTEL traces
- Add workflow for generating binary during release (#33)
- Updated assert-benchmark script, removed unnecessary code, changed func visiblity
- Rearanged packages
- Created procedure package
- Rearanged code
- Updated server to work with timestamps for validity
- Re-generated proto
- Implemented Benchmark procedure
- Rename CryptoBroker to CryptoGrpc and add Benchmark methods in gRPC server
- Add health check service to gRPC server (#85)

### 🐛 Bug Fixes

- Adjust env variables (#58)
- Updated socker file name
- Updated README.MD by removing linting errors
- Updated naming of function
- Updated bench name
- Updated bench names
- Update BasicConstraintsValid to use input.IsCA in SignCertificate method (#47)
- Updated readme
- Fixed lint errors in readme
- Fixed docs misleading
- Fixed modulo issue
- Init submodule without the proto dependency (#44)
- Added proto dependency for build-docker task (#41)
- Added missing validation for ca private key (#36)

### 🚜 Refactor

- Optimize benchmark execution by using testing.Benchmark for improved timing (#35)
- Adjust Task setup (#32)

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
