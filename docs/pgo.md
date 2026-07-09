## Overview

Profile-guided optimization (PGO), also known as feedback-directed optimization (FDO) is a compiler optimization technique that feeds information (a profile) from representative runs of the application back into to the compiler for the next build of the application, which uses that information to make more informed optimization decisions.

This document describes how [PGO](https://go.dev/doc/pgo) was implemented in `crypto-broker-server`.

## Table of contents

- [Implementation](#implementation) - general description of implementation and how to use it
    - [How to get server profile data](#how-to-get-server-profile-data)
    - [How to build server binary with PGO](#how-to-build-server-binary-with-pgo)
    - [How to assess whether optimization worked](#how-to-get-server-profile-data)
        - [Prerequisite](#prerequisite) - what you need before assesment
        - [General flow](#general-flow) - high level overview of process steps
        - [Exact steps](#exact-steps) - detailed steps to follow

## Implementation

To provide ability of ingesting profiling data, `"net/http/pprof"` server was added to `crypto-broker-server` binary. It can be only turned on in dev mode:

- `.env` (loaded by Taskfile): `APP_ENV=dev`
- `CRYPTO_BROKER_APP_ENV=dev` in shell for direct access by server (when not using Taskfile).

Having that, user need to provide server address and port through:

- `.env` (loaded by Taskfile): `PPROF_ADDR=127.0.0.1:6060`
- `CRYPTO_BROKER_PPROF_ADDR=127.0.0.1:6060` in shell for direct access by server (when not using Taskfile).

When successfully turned on, following bootstrap phase logs will be displayed:

```text
{"time":"2026-05-18T08:13:40.812277885+02:00","level":"INFO","msg":"pprof HTTP server listening","service":"crypto-broker-server","address":"127.0.0.1:6060"}
```

### How to get server profile data

To build binary with profiling data you need to get that data first. You can follow these steps to do it.

1. Configure server settings through Taskfile (`APP_ENV="dev"` + `PPROF_ADDR=127.0.0.1:6060` are mandatory, other are up to you).
2. Run the server with pprof - `task run`
3. Change directory to `crypto-broker-cli-go` and run e2e benchamarks with `task run-benchmarks` - this should take at least few seconds
4. Meantime in second terminal or shell download server's profile with `curl -sS -o cpu.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'`.

Please note that step 3 may end quickly, so you'll need to re-run it quickly when it finishes. Goal is to have meaningful load on server during profile scrapping in point 4.

### How to build server binary with PGO

Having `cpu.pprof` you can manually build server with `pgo` using `go build -pgo=cpu.pprof -o crypto-broker-server-pgo ./cmd/server` from `crypto-broker-server` dir.

### How to assess whether optimization worked

#### Prerequisite

Install `benchstat` program with `go install golang.org/x/perf/cmd/benchstat@latest`.

#### General flow

1. Get benchmark output from server that *is not* build with PGO
2. Get benchmark output from server that *is* build with PGO
3. Compare it using *benchstat* program to understand difference

#### Exact steps

1. Run the server without PGO (`task run`)
2. Go to `crypto-broker-cli-go` and run: `go test ./... -count=5 -benchmem -run=^$ -bench ^Benchmark > ../bench-baseline.txt 2>&1`
3. Run the server with PGO
4. Go to `crypto-broker-cli-go` and run: `go test ./... -count=5 -benchmem -run=^$ -bench ^Benchmark > ../bench-pgo.txt 2>&1`
5. Examine difference using `benchstat bench-beseline.txt bench-pgo.txt`
