# Changelog

The list of commits in this changelog is automatically generated in the release process.
The commits follow the Conventional Commit specification.

## [0.3.0] - 2026-06-08

### 🚀 Features

- Update golang version from 1.26.3 to 1.26.4 (#113)
- Check if crlDistributionPoints are valid URLs (#112)
- Added validation for ID and CorrlationID fields
- [**breaking**] Updated proto reference which removed created_at
- Added support for few environment variables related to logging in Taskfile, updated docs
- Added pprof docs
- Add license check (#105)
- Enhance input validation tests for Hash and Sign requests (#106)
- Implement input validation for gRPC requests (#95)
- Linted code
- Added pprof server for dev mode + PGO guideline
- Add version sync check workflow (#103)
- Updated README by splitting it into smaller files
- Added ability to turn on/off fips140 enforcement
- Added environment variable that allows to switch fips module version
- Added disclaimer to benchmark-assert.sh script
- Added calculated thresholds and marked 'Assert benchmark perfrmance' workflow step as required to pass
- Added formula for thresholds
- Add depependabot config (#92)

### 🐛 Bug Fixes

- Removed trailing space
- Fixed linting issues
- Fixed issues with *.md and golangci-lint
- Extract FakeEndpoint and Benchmark endpoints to separate service (#98)
- Fixed makrdown lint issues
- Adde ceil to ns/op thresholds
- Add Persist Credentials to workflows (#94)

### 💼 Other

- Bump go version from 1.26.2 to 1.26.3 (#99)

### 🚜 Refactor

- Adjust workflow files (#102)

### ⚙️ Miscellaneous Tasks

- Update grpc-health-probe (#100)

## [0.2.2] - 2026-04-24

### 🐛 Bug Fixes

- Adjust release permission (#91)
- Adjust permissions for docker release, add GitHub release stage (#90)
- Return InvalidArgument status code (#89)
- Add id-token permission (#88)

## [0.2.1] - 2026-04-20

### 🚀 Features

- Added bootstrap time trace probe
- Injected git sha and git commit during build time
- Update submodule commit reference in protobuf (#84)
- Use hash tagged actions, fix lint issues (#77)
- Updated go deps & updated required minimial go version
- Add workflow lint (#78)
- Added golangci-lint installation
- Added golangci-lint to local pipeline
- Added config file
- Removed problematic unit tests

### 🐛 Bug Fixes

- Adjust permissions for release workflow (#87)
- Remove persist credentials (#86)
- Simplified Taskfile command
- Refactor workflow lint action (#81)
- Adjust permissions for nightly workflow (#82)
- Fixed linting issues
- Add artifact-metadata in release workflow for docker stage (#75)

### ⚙️ Miscellaneous Tasks

- Update grpc-health-probe in Dockerfile (#79)

## [0.2.0] - 2026-03-31

### 🚀 Features

- Removed test-case
- Updated test cases coverage & fixed bugs

### ⚙️ Miscellaneous Tasks

- Update actions to latest versions for Node 24 support (#73)

## [0.1.1-rc6] - 2026-03-23

### 🚀 Features

- Add nightly security scan (#70)
- Collectively updated dependencies
- Updated go-grpc-middleware/v2
- Updated go-yaml dep
- Renamed package grpcmw to interceptors
- Moved logic to middlewares
- Implemented correlationId support for traces
- Updated proto reference and re-generated messages
- Update go version to latest
- Add two upload paths for Grype scans (#62)
- Removed not needed 'go version' invokement in Taskfile, updated workflow by adding new step related to FIPS mode benchmarks
- Updated build command so it displays details of server binary
- Added env command to Taskfile, added .env as dependency for build command
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

- Adjust Dockerfile (#68)
- Remove OCM support (#67)
- Adjust env file and Taksfile (#65)
- Add submodule checkout (#63)
- Linted code
- Fixed service name & version issue and refactored code
- Adjust release workflow (#61)
- Adjust release workflow (#60)
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
