## Overview

This document explains FIPS 140-3 compliance and how to enable it in the `crypto-broker-server`.

### What is FIPS

FIPS (Federal Information Processing Standards) are U.S. government standards published by the National Institute of Standards and Technology (NIST) for computer systems used by federal agencies.

FIPS 140-3 defines security requirements for cryptographic modules — software or hardware components that perform operations such as encryption, hashing, signing, and key generation.

### How Go implements FIPS 140-3

Go FIPS compliance means configuring the Go cryptographic stack to use a FIPS-validated module rather than the default unvalidated implementation. Concretely, this involves two steps: linking the validated module at build time, and activating it at runtime.

For background, see the official documentation:

* [FIPS 140-3 Compliance](https://go.dev/doc/security/fips140)
* [The FIPS 140-3 Go Cryptographic Module](https://go.dev/blog/fips140)
* [Go Cryptography Security Audit](https://go.dev/blog/tob-crypto-audit)

#### `GOFIPS140` values and certification status

`GOFIPS140` is the build-time environment variable that controls which FIPS module the Go toolchain links into the binary:

| Value | Effect |
| ----- | ------ |
| `off` | No FIPS module linked (default) |
| `latest` | Built-in toolchain FIPS module — not certified or frozen; not suitable for production FIPS compliance |
| `inprocess` | FIPS module linked; non-approved algorithms still permitted at runtime |
| `v1.Y.Z` (e.g. `v1.0.0`) | Specific certified, frozen module version — use for production FIPS compliance |

`v1.Y.Z` values are **Go Cryptographic Module version numbers** — internal identifiers assigned by the Go team to frozen snapshots of `crypto/internal/fips140/...`. They are not CMVP certificate numbers.

**Frozen** means the module source code is snapshotted at a specific commit and archived as an immutable zip (e.g. `v1.0.0-c2097c7c.zip` in the Go source tree). NIST tests exact bytes, so this immutability is a hard requirement for certification. Bug fixes applied to the live Go crypto code do not update a frozen snapshot — a new version must be submitted and certified separately.

**CMVP** (Cryptographic Module Validation Program) is the NIST program that issues certificates for validated modules. **CAVP** (Cryptographic Algorithm Validation Program) certifies the individual algorithms inside a module. A module typically receives a CAVP certificate first, then a CMVP certificate after the full module review completes.

| `GOFIPS140` value | Frozen | Minimum Go version | CMVP status |
| ----------------- | ------ | ------------------ | ----------- |
| `v1.0.0` | Early 2025 | Go 1.24 | ✅ Certified — CMVP [#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247) (vendor Geomys LLC, issued 27 April 2026), CAVP [A6650](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=19371) (first validated 6 March 2025) |
| `v1.26.0` | Early 2026 | Go 1.26 | ⏳ In Review (as of July 2026) — no CMVP certificate yet, CAVP [A8028](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=40638)  (first validated 18 February 2026) |

> **Note:** CMVP #5244 (BoringCrypto, vendor Google LLC) is the previous, deprecated mechanism and should not be used for new deployments. The current certified module is `v1.0.0` under CMVP #5247, maintained by Geomys LLC (Filippo Valsorda).

For production deployments that require a certified module, use `GOFIPS140=v1.0.0` with Go 1.24 or later.

### How `crypto-broker-server` works with FIPS

For a general introduction, see the ["A native developer experience"](https://go.dev/blog/fips140#a-native-developer-experience) section of the Go FIPS blog post.

FIPS mode in `crypto-broker-server` is controlled by two independent levers:

* **Build time:** `GOFIPS140` determines which cryptographic module is linked into the binary.
* **Runtime:** `GODEBUG` determines whether the FIPS module is merely enabled or strictly enforced.

The sections below describe how to configure both, depending on the development or deployment context.

#### Locally

The recommended local workflow uses the [Taskfile](./../Taskfile.yaml), which reads FIPS-related settings from the `.env` file (see [.env.example](./../.env.example)). Note that the Taskfile variables are read by Taskfile itself — they are distinct from the [environment variables](./envs.md) read by the server binary at runtime.

The relevant Taskfile variables are:

| Variable | Default | Description | Valid values |
| -------- | ------- | ----------- | ------------ |
| `FIPS_MODE_ENABLED` | - | Whether to enable FIPS mode | `true`, `false` |
| `FIPS_MODE_MODULE_VERSION` | - | Go Cryptographic Module version to link (`GOFIPS140` at build time) | `v1.0.0`, ... |
| `FIPS_GODEBUG_VALUE` | - | `GODEBUG` value applied when the server starts | `fips140=on`, `fips140=only`, `fips140=off` |

When `FIPS_GODEBUG_VALUE` is set to `fips140=only`, the Go runtime rejects any call to a non-FIPS-compliant algorithm. The server's built-in recovery middleware catches the resulting panic and returns it as a server error rather than terminating the process. For example:

```text
crypto/md5: use of MD5 is not allowed in FIPS 140-only mode
```

#### Without Taskfile

Without Taskfile, the build-time and runtime steps must be performed explicitly. The Taskfile variables map directly to the underlying Go mechanisms: `FIPS_MODE_MODULE_VERSION` → `GOFIPS140` at build time; `FIPS_GODEBUG_VALUE` → `GODEBUG` at runtime.

##### Step 1 — Build the binary with the FIPS module linked

Set `GOFIPS140` before running `go build` to instruct the Go toolchain to link the FIPS 140-3 validated cryptographic module:

```bash
GOFIPS140=v1.0.0 go build \
  -o bin/crypto-broker-server \
  -ldflags="-X main.gitSHA=$(git rev-parse --short HEAD) -X main.gitTag=$(git describe --tags --always)" \
  cmd/server/server.go
```

> **Note:** `GOFIPS140` is consumed by the Go toolchain at build time. It has no effect if set at runtime.

To verify the binary was built with the FIPS module linked:

```bash
go version -m bin/crypto-broker-server | grep fips
```

##### Step 2 — Start the server in FIPS strict mode

Set `GODEBUG=fips140=only` when launching the binary to restrict the runtime to FIPS-compliant algorithms only:

```bash
GODEBUG=fips140=only ./bin/crypto-broker-server
```

Use `fips140=on` instead of `fips140=only` to activate the FIPS module while still permitting non-compliant algorithms — useful during a transition period or for testing.

#### Deploying to a platform

The build step above belongs in CI/CD and is performed once before deployment. The resulting binary or container image is then deployed with `GODEBUG` configured through the platform's runtime environment mechanism.

##### Cloud Foundry

Set `GODEBUG` in the `env` section of the application manifest. The `binary_buildpack` executes the pre-built binary directly and does not invoke `go build` during staging, so `GOFIPS140` is not required in the CF environment.

```yaml
applications:
  - name: crypto-broker-server
    buildpacks:
      - binary_buildpack
    command: ./bin/crypto-broker-server
    env:
      GODEBUG: fips140=only
```

##### Kubernetes

Set `GODEBUG` in the container environment of the pod specification. The container image must have been built with `GOFIPS140` set at image build time.

```yaml
containers:
  - name: crypto-broker-server
    image: <your-registry>/crypto-broker-server:latest
    env:
      - name: GODEBUG
        value: "fips140=only"
```
