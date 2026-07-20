# Security

## Packages

This repository contains two threshold signature packages:

- **`dkls23/`** — Threshold ECDSA over secp256k1 (DKLS23 paper, IEEE S&P 2024)
- **`frost/`** — Threshold Schnorr / Ed25519 (IETF RFC 9591, FROST)

Both packages share the same threat model and security principles described
below, with protocol-specific details noted where they differ.

## Threat Model

Both packages implement t-of-n threshold signature protocols with honest majority.
The following assumptions apply:

- All parties communicate over authenticated point-to-point channels (e.g., TLS
  or Noise Protocol Framework). Neither package provides a transport
  layer — callers must ensure channel authentication and confidentiality.
- The master secret key is never reconstructed in a single location. Each party
  holds only a Shamir secret share.

### Cheating Detection

#### dkls23

Cheating parties are detected at multiple protocol stages:

- **VOLE consistency check**: Malicious correlation values are caught via a
  SHAKE-256 proof verified with constant-time comparison
  (`subtle.ConstantTimeCompare`).
- **R-commitment decommitment**: Parties commit to nonce shares in signing
  round 1 and decommit in round 2. Inconsistencies are detected and the
  cheating party is identified.
- **Blacklisting**: Detected cheaters are permanently blacklisted via
  `SignerSetup.Blacklist` and rejected from all future signing sessions.

#### frost

Cheating detection in FROST is simpler due to Schnorr's linearity:

- **Feldman VSS verification**: Each party's DKG share is verified against
  broadcast Feldman commitments. Inconsistent shares are detected.
- **Signature share verification**: The aggregator can verify each individual
  signature share (`z_i * B == D_i + rho_i * E_i + c * lambda_i * PK_i`),
  enabling identifiable abort — the specific misbehaving signer is identified.
- **Blacklisting**: Detected cheaters are permanently blacklisted via
  `SignerState.Blacklist` and rejected from all future signing sessions.

### Proactive Key Refresh

Both packages support proactive key share refresh — rotating shares without
changing the master public key. This limits the exposure window if a share
is compromised.

#### dkls23
- Shamir shares re-randomized using zero-constant Feldman VSS polynomials.
- VOLE correlations and FZero seeds refreshed alongside shares (KMOS21).
- Refresh sessions tracked by epoch to prevent replay.

#### frost
- Shamir shares re-randomized using zero-constant Feldman VSS polynomials.
- Verification shares updated to match new secret shares.
- No VOLE/OT state (FROST has none). Simpler than dkls23 refresh.
- Refresh sessions tracked by epoch to prevent replay.

## Constant-Time Guarantees

All operations on secret values are designed to execute in constant time,
preventing timing side-channel attacks on shared hardware.

### dkls23

- **Scalar arithmetic**: All secret scalar operations use btcec's constant-time
  `ModNScalar`. Modular inversion uses a constant-time Fermat's little theorem
  implementation (`scalarInverse`: `a^(q-2) mod q` via square-and-multiply with
  fixed public exponent). No `math/big` arithmetic is performed on secret values.
- **VOLE Beta selection**: Bob's secret binary vector β is never used as a
  branch condition. All β-dependent operations use branchless multiply-by-mask
  (`condUint32(β) * value`) or `subtle.ConstantTimeCopy` for byte selection.
- **Commitment verification**: FCom opening and VOLE proof checks use
  `subtle.ConstantTimeCompare`.
- **Zeroization**: Ephemeral secrets are zeroized via `ModNScalar.Zero()`
  (deterministic, not subject to GC interference).

The only remaining `math/big` usage is `reduce64Public`, which reduces 64-byte
public hash outputs (Fiat-Shamir challenges, FZero hashes) modulo q. These
are derived from public data and are not timing-sensitive.

### frost

- **Scalar arithmetic**: All secret scalar operations use `filippo.io/edwards25519`
  constant-time `Scalar` methods (`Add`, `Multiply`, `Subtract`). Modular
  inversion uses a constant-time Fermat's little theorem implementation
  (`scalarInverse`: `a^(L-2) mod L` via square-and-multiply with fixed public
  exponent). No `math/big` arithmetic is performed on secret values.
- **Nonce generation**: Hedged via RFC 9591's `nonce_generate`:
  `H3(random_bytes(32) || secret)`. Mixes CSPRNG output with the secret key
  to protect against weak RNG.
- **Commitment verification**: DKG share commitments use `subtle.ConstantTimeCompare`.
- **Zeroization**: Signing nonces (`HidingNonce`, `BindingNonce`) are zeroized
  to the zero scalar after `SignRound2` computation. The `nonceGenerate` input
  buffer (containing the secret key) is explicitly zeroed after hashing.
- **Nonce reuse prevention**: `Round1State.consumed` flag prevents a second call
  to `SignRound2` with the same nonces. Reuse would enable full key recovery.

## Test Coverage

Both packages maintain comprehensive test suites with 90%+ statement coverage:

- **dkls23**: 15 test files, 12 fuzz targets, 48 unmarshal error cases, race-detector clean.
- **frost**: 12 test files, 11 fuzz targets, 20 unmarshal error cases, race-detector clean.

Edge-case tests cover malicious inputs (corrupted commitments, non-canonical
scalars, off-curve points, truncated shares), nonce reuse prevention,
post-persistence functional round-trips, and identifiable abort.

## Known Limitations

- **Memory retention**: Go's garbage collector may retain copies of
  intermediate stack values after zeroization. When built with
  `GOEXPERIMENT=runtimesecret` (Go 1.26+, linux/amd64 and linux/arm64),
  all exported functions that handle secret material are wrapped in
  `runtime/secret.Do`, which erases registers, stack, and heap used by
  the function after it returns. On other platforms, the fallback is
  direct invocation with manual `Zero()` calls (defense-in-depth).
  (Applies to both packages.)
- **Random oracle model**: dkls23 uses SHAKE-256; frost uses SHA-512. Both
  are modeled as random oracles in their respective protocol security proofs.
- **Physical attacks**: No protection is provided against physical
  side-channel attacks (power analysis, electromagnetic emanation, etc.).
  (Applies to both packages.)
- **No independent human audit**: Both packages have been audited by Claude
  Code (Anthropic Claude Opus 4.6), which performed source code
  review, protocol equation verification against the DKLS23 paper and RFC 9591,
  compiler output disassembly, escape analysis, fuzz testing, and dependency
  vulnerability scanning. dkls23 had 10 findings (all resolved); frost had
  4 findings (all resolved). The full report is in [`AUDIT.md`](AUDIT.md).
  This is not a substitute for an independent third-party audit by a firm
  specializing in MPC protocols, and the code has not been formally verified.

## Responsible Disclosure

If you discover a security vulnerability in this project, please report it
through GitHub Security Advisories (private vulnerability reporting):

<https://github.com/chrisalmeida/go-mpc/security/advisories/new>

Do not open a public issue for security vulnerabilities.

## Dependencies

| Dependency                          | Used by | Purpose                                                                               |
| ----------------------------------- | ------- | ------------------------------------------------------------------------------------- |
| `github.com/btcsuite/btcd/btcec/v2` | dkls23  | secp256k1 curve operations (constant-time scalar arithmetic and point multiplication) |
| `filippo.io/edwards25519`           | frost   | Ed25519 curve operations (constant-time scalar and point arithmetic, RFC 8032 encoding) |
| `golang.org/x/crypto`               | dkls23  | SHAKE-256 (OT hashing, Fiat-Shamir challenges, VOLE proofs)                           |
| `github.com/stretchr/testify`       | both    | Test assertions only (not used in production code)                                    |
