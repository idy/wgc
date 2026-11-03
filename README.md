# WGC

[![CI](https://github.com/idy/wgc/actions/workflows/ci.yml/badge.svg)](https://github.com/idy/wgc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/idy/wgc.svg)](https://pkg.go.dev/github.com/idy/wgc)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**WireGuard connections for Go.** WGC exchanges authenticated, encrypted messages
between peers identified by public keys. It implements WireGuard handshakes,
sessions, rekeying, replay protection, and peer roaming over a pluggable transport.

[Project page](https://wgc.idy.dev/) · [API reference](https://pkg.go.dev/github.com/idy/wgc) · [Runnable example](examples/echo/main.go)

## Install

Requires Go 1.25 or later.

```sh
go get github.com/idy/wgc
```

The module is `github.com/idy/wgc`. Its Go package name is `wireguard`, preserving
the original connection API.

```go
import (
    "net"

    wireguard "github.com/idy/wgc"
    "github.com/idy/wgc/transport"
)
```

## Run the example

```sh
go run ./examples/echo
```

The example generates two ephemeral key pairs, opens two local UDP endpoints,
authorizes only the other peer, and sends an encrypted echo through a real
WireGuard handshake. It requires no TUN device, root privileges, or external
server. Expected output includes `Received authenticated echo: hello, wgc`.

## Use a connection

Generate or load the local private key, authorize remote public keys, and provide
the endpoint for peers this connection should initiate a handshake with:

```go
socket, err := net.ListenUDP("udp", &net.UDPAddr{Port: 51820})
if err != nil {
    return err
}
conn, err := wireguard.NewConn(transport.FromUDPConn(socket), wireguard.Config{
    StaticPrivateKey: &privateKey,
    MaxPeers:         128,
    PeerConfigLookup: func(key wireguard.Key) (*wireguard.PeerConfig, error) {
        if key != remotePublicKey {
            return nil, nil // Reject unknown peers.
        }
        return &wireguard.PeerConfig{Addr: remoteEndpoint}, nil
    },
})
if err != nil {
    socket.Close()
    return err
}
defer conn.Close()

if _, _, err := conn.WriteTo([]byte("hello"), remotePublicKey); err != nil {
    return err
}
buffer := make([]byte, wireguard.MaximumDataSize)
n, peer, err := conn.ReadFrom(buffer)
```

`privateKey`, `remotePublicKey`, and `remoteEndpoint` are application-supplied
values. See the complete [echo example](examples/echo/main.go) for their setup.

`ReadFrom` returns the authenticated sender. `WriteTo` selects a peer by public
key and queues a message; encryption and transmission happen asynchronously.
A successful return means the message was queued, not delivered. A write can
trigger a handshake and be discarded while no session is available. Use
application acknowledgements and retries when delivery matters, as the echo
example does. `PeerWriter` provides a reusable writer for a selected peer.
The API is message-oriented and does not implement `net.Conn` or `net.PacketConn`
directly; it does not guarantee delivery or ordering. Keep a read loop running,
since WireGuard keepalives can appear as empty messages. Messages larger than
`MaximumDataSize`, including the combined size of a chunked write, return
`ErrMessageTooLarge` before entering a queue.

For a receive queue, range over `conn.ReadQueue()` and call `packet.Release()`
after consuming each packet. Packet bytes are pooled; copy them before retaining
them beyond `Release`. Do not combine queue reads and `ReadFrom` on one connection.

## Peers and resource limits

- `PeerConfigLookup` authorizes a new public key. Returning `nil` denies it;
  returning an error permits a future lookup retry. A successful result is cached.
- `PeerConfig.PSK` adds an optional preshared key. Both peers must use the same key.
- Authenticated packets update the remote endpoint unless `DisableAddrRoaming`
  is set. `DisableHandshakeInitiation` supports passive peers.
- `Config.MaxPeers` bounds live peer state. Zero preserves the original unlimited
  behavior; set a limit for listeners exposed to untrusted peers.
- `ReadQueueSize` and `WriteQueueSize` default to 1024.
- `SharedWriteQueue` shares the connection's write queue across destinations.
  Otherwise, `WriteTo` queues belong to admitted peers and retire on eviction.
  Explicit `PeerWriter` values retain their own queues across peer eviction.
- `DisableStats` disables peer history and traffic counters. Otherwise,
  `CaptureStats` captures and resets the counters, returning the captured
  interval's start time.
- `Close` closes the underlying transport and unblocks pending I/O.

## Transports

The public `transport` package contains one implementation: `FromUDPConn` adapts
an existing listening `*net.UDPConn` to the connection API. It sends and receives
standard WireGuard messages without additional framing. Closing the adapter
closes the supplied socket.

Applications can supply another implementation of `wireguard.Transport`:

```go
type Transport interface {
    ReadFrom([]byte) (int, netip.AddrPort, error)
    WriteTo([]byte, netip.AddrPort) (int, error)
    Close() error
}
```

Pass the implementation to `wireguard.NewConn(applicationTransport, config)`.
Custom framing, socket policies, and other application-specific transport
behavior belong in the application; WGC does not include their implementations.
A transport must support a reader and concurrent writers, avoid retaining the
supplied buffers after each method returns, and unblock pending I/O on `Close`.

WGC does not create a VPN interface, manage IP addresses, install routes, or
provide a TCP/IP stack. Stock WireGuard peers expect IP packets as payloads;
applications exchanging arbitrary messages should use WGC at both ends.

## Logging

By default, normal messages, warnings, and errors use Go's standard `log` package;
debug verbosity is suppressed. `SetLogHandler` installs a concurrent-safe,
process-wide callback. Verbosity values are -2 for errors, -1 for warnings,
0 for normal messages, and positive for debug detail. Pass `nil` to restore the
default. Never enable detailed protocol logs where their contents are sensitive.

## Development

```sh
go test -race ./...
go test -tags BUFPOOL_MINI ./...
go vet ./...
go run ./examples/echo
```

Public integration, regression, and benchmark suites live under [`tests/`](tests/README.md).
Run a suite with `go test -race ./tests/integration/...` or
`go test -race ./tests/regression/...`, and run public benchmarks with
`go test -run '^$' -bench . -benchmem ./tests/benchmark/...`.
White-box tests and microbenchmarks stay beside the Go packages whose private
state they exercise. The full `go test ./...` commands discover all test packages;
benchmarks run when `-bench` is specified.

Tests cover handshake helpers, bounded peer state, concurrent shutdown,
authenticated transport messages, replay rejection, real encrypted UDP echoes,
and transport shutdown. `BUFPOOL_MINI` selects a smaller standard-library buffer pool;
the default pool uses gVisor's buffer implementation. This is the existing pool
behavior, and the build tag changes `MaximumMessageSize` and `MaximumDataSize`.

Key files:

- `conn.go`, `peer.go`, and `secure_session.go`: connections, peer lifecycle,
  handshakes, and encrypted sessions.
- `queue_io.go` and `writer.go`: packet ownership and queued writes.
- `transport/`: the standard UDP socket adapter.
- `internal/`: protocol headers, cryptographic helpers, buffers, timestamps,
  backoff, and logging.
- `examples/echo/`: a self-contained local exchange.
- `tests/`: public integration tests, regressions, benchmarks, and shared fixtures.
- `site/`: the static project page, published to `wgc.idy.dev` by GitHub Pages.

## License

WGC is available under the [MIT License](LICENSE). Third-party code and modules
retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
WireGuard is a registered trademark of Jason A. Donenfeld. This is an independent
project and does not imply endorsement by the WireGuard project.
