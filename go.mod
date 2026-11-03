module github.com/idy/wgc

go 1.25.0

retract v0.1.0 // Superseded by the minimal public transport distribution.

require (
	golang.org/x/crypto v0.55.0
	golang.zx2c4.com/wireguard v0.0.0-20230704135630-469159ecf7d1
	gvisor.dev/gvisor v0.0.0-20240306221502-ee1e1f6070e3
)

require (
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.5.0 // indirect
)
