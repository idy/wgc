# Third-party notices

WGC's project code is licensed under the MIT License in `LICENSE`. Dependencies
retain their own licenses, copyrights, and notices. Exact versions and checksums
are recorded in `go.mod` and `go.sum`.

- `golang.zx2c4.com/wireguard/replay` comes from WireGuard's Go implementation,
  Copyright Jason A. Donenfeld and contributors, under the MIT License.
  `internal/utils/utils.go` also references its key generation helper. The
  upstream license is preserved in `LICENSES/wireguard-go.txt`.
- `golang.org/x/crypto` and `golang.org/x/sys` are Go
  subrepositories, Copyright The Go Authors, under BSD-style licenses. Their
  license texts are preserved in `LICENSES/`.
- `gvisor.dev/gvisor/pkg/buffer` and its supporting packages come from gVisor,
  Copyright The gVisor Authors, under Apache-2.0. The upstream license and
  contributor attribution are preserved in `LICENSES/`.

No monorepo application source, deployment inventory, signing material, or
repository history is included in this distribution.
