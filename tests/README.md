# Tests and benchmarks

Run commands from the repository root. Go 1.25 or later is required.

## Layout

| Location | Purpose |
| --- | --- |
| `tests/integration/` | Public API integration tests, including real localhost UDP handshakes and authenticated echoes with and without a preshared key. |
| `tests/regression/` | Public API regression cases for key parsing, write bounds, shutdown, and oversized UDP datagrams. |
| `tests/benchmark/` | Public API benchmarks for key decoding and key generation. |
| `tests/internal/testutil/` | Shared sockets, peer-pair setup, and bounded I/O helpers for these suites. |
| Root `*_test.go` and `internal/**/*_test.go` | White-box unit and regression tests and microbenchmarks that access package-private protocol, queue, timer, buffer, or logging state. |
| `transport/udp_error_windows_test.go` | Windows-only white-box coverage of the UDP error classifier. |

Go compiles each directory as a separate package. White-box tests stay beside the implementation so they can access unexported symbols without adding test-only exports to the library. Public API tests under `tests/` import WGC as a caller would.

## Run tests

All packages, including both public suites and colocated white-box tests:

```bash
go test -race ./...
```

The smaller buffer implementation:

```bash
go test -race -tags BUFPOOL_MINI ./...
```

Only the real UDP integration suite:

```bash
go test -race ./tests/integration/...
```

Only public regression cases:

```bash
go test -race ./tests/regression/...
```

The UDP suites use loopback sockets, ephemeral ports, and bounded waits. They require no TUN interface, elevated privileges, or external server. Platform-specific regressions run on their target operating system.

## Run benchmarks

Public API benchmarks with allocation counts:

```bash
go test -run '^$' -bench . -benchmem ./tests/benchmark/...
```

Include colocated handshake, buffer, and logging microbenchmarks:

```bash
go test -run '^$' -bench . -benchmem ./...
```

Smoke-test every benchmark with one iteration:

```bash
go test -run '^$' -bench . -benchtime=1x ./...
```

Benchmark timing is informational; there are no machine-dependent timing thresholds. Use the same Go version, build tags, and host when comparing results.

The existing CI `go test ./...` commands discover the new suites automatically.
