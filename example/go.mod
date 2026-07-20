module go-mpc-example

go 1.26

require (
	filippo.io/edwards25519 v1.2.0
	github.com/btcsuite/btcd/btcec/v2 v2.3.6
	github.com/seabond/go-mpc v0.0.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
)

replace github.com/seabond/go-mpc => ../
