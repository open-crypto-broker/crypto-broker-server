# Runtime profiling (pprof)

Guide for finding CPU and memory hotspots in `crypto-broker-server` using Go’s built-in [`net/http/pprof`](https://pkg.go.dev/net/http/pprof).

For **compiler** optimization with the same CPU profiles, see [pgo.md](./pgo.md).

## When profiling is available

pprof is started only when **both** are true:

1. `CRYPTO_BROKER_APP_ENV=dev` (Taskfile: `APP_ENV=dev`)
2. `CRYPTO_BROKER_PPROF_ADDR` is set (Taskfile: `PPROF_ADDR`, e.g. `127.0.0.1:6060`)

The server registers these HTTP routes (`cmd/server/server.go`):

| Path | Purpose |
| ------ | --------- |
| `/debug/pprof/` | Index (links to all profile types) |
| `/debug/pprof/profile` | CPU profile (blocking sample) |
| `/debug/pprof/heap` | Heap memory (via index handler) |
| `/debug/pprof/goroutine` | Goroutine stacks |
| `/debug/pprof/trace` | Execution trace (latency, scheduling) |
| `/debug/pprof/cmdline`, `/debug/pprof/symbol` | Debug helpers |

Use **loopback only** (`127.0.0.1`). Do not expose pprof on production networks.

Confirm it is up: logs contain `pprof HTTP server listening` with your address.

## Quick start

1. Copy and edit env (see [development.md](./development.md)):

   ```bash
   cp .env.example .env
   # APP_ENV=dev
   # PPROF_ADDR=127.0.0.1:6060
   ```

2. Terminal A — run server:

   ```bash
   task run
   ```

3. Terminal B — generate realistic load while you profile (e.g. benchmarks or CLI against the Unix socket):

   ```bash
   task run-benchmarks
   # or use crypto-broker-cli-go e2e benchmarks
   ```

4. Terminal C — capture a CPU profile (30s sample; run during load in terminal B):

   ```bash
   curl -sS -o cpu.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
   ```

5. Explore interactively:

   ```bash
   go tool pprof -http=127.0.0.1:8080 cpu.pprof
   ```

   Open the URL in a browser. Start with **Top** and **Flame Graph** to see where time is spent.

## Profiles to use when optimizing

| Goal | Capture | Analyze |
| ------ | --------- | --------- |
| Slow RPC / hot functions | CPU: `curl …/profile?seconds=30` | `go tool pprof -http=… cpu.pprof` — focus on `flat` + `cum` % |
| High allocations | Heap while under load: `curl -sS -o heap.pprof 'http://127.0.0.1:6060/debug/pprof/heap'` | `go tool pprof -alloc_space -http=… heap.pprof` |
| Goroutine leak / stall | `curl -sS -o goroutine.pprof 'http://127.0.0.1:6060/debug/pprof/goroutine'` | `go tool pprof goroutine.pprof` — compare two snapshots |
| Latency / scheduling | Trace: `curl -sS -o trace.out 'http://127.0.0.1:6060/debug/pprof/trace?seconds=5'` | `go tool trace trace.out` |

**CPU:** Profile must overlap with real work; an idle server gives an empty or misleading profile.

**Heap:** Take a snapshot after warm-up and repeated requests; look for large `alloc_space` in your packages (`internal/procedure`, `internal/api`, etc.).

**Compare before/after:** Save `cpu-before.pprof` / `cpu-after.pprof`, then:

```bash
go tool pprof -http=127.0.0.1:8080 -base=cpu-before.pprof cpu-after.pprof
```

Positive diff = more time in that function after your change.

## CLI tips (no browser)

```bash
go tool pprof -top cpu.pprof          # hottest functions
go tool pprof -list=HashData cpu.pprof    # source lines for symbol HashData
go tool pprof -text -nodecount=20 cpu.pprof
```

Install the web UI helper once if needed: `go install github.com/google/pprof@latest`.

## Workflow for a performance fix

1. Reproduce slowness with a fixed benchmark or CLI script (same inputs every run).
2. Capture CPU profile **during** that workload (20–60s is typical).
3. Identify top `cum` frames in project code (ignore runtime/stdlib unless they dominate).
4. Change one thing; re-profile and compare with `-base`.
5. Confirm with `go test -bench=… -benchmem` or deployment benchmarks — pprof shows *where* time went, not absolute SLA.

## Environment reference

| Taskfile / `.env` | Server env var |
| ------------------- | ---------------- |
| `APP_ENV=dev` | `CRYPTO_BROKER_APP_ENV` |
| `PPROF_ADDR=127.0.0.1:6060` | `CRYPTO_BROKER_PPROF_ADDR` |

Full list: [envs.md](./envs.md).

## Related

- [pgo.md](./pgo.md) — feed `cpu.pprof` into `go build -pgo=…`
- [development.md](./development.md) — local run and benchmarks
