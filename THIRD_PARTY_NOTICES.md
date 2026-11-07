# Third-party notices

WGC's project code is licensed under the MIT License in `LICENSE`. Dependencies
retain their own licenses, copyrights, and notices. Exact versions and checksums
are recorded in `go.mod` and `go.sum`.

- `internal/replay/replay.go` and `replay_test.go` are unchanged copies from
  `golang.zx2c4.com/wireguard/replay` at commit
  `469159ecf7d1` (`v0.0.0-20230704135630-469159ecf7d1`), Copyright (C)
  2017-2023 WireGuard LLC, under the MIT License. The source headers and upstream
  tests are preserved. `internal/utils/utils.go` also references WireGuard's key
  generation helper. The upstream license is in `LICENSES/wireguard-go.txt`.
  Keeping this small package locally avoids a module dependency on WireGuard's
  unused TUN and gVisor networking stack.
- `golang.org/x/crypto` and `golang.org/x/sys` are Go
  subrepositories, Copyright The Go Authors, under BSD-style licenses. Their
  license texts are preserved in `LICENSES/`.

No monorepo application source, deployment inventory, signing material, or
repository history is included in this distribution.
