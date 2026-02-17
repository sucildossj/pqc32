# BIP-PQC32: Post-Quantum HD Wallet Standard for SLH-DSA

```
  BIP: PQC32
  Layer: Applications
  Title: Post-Quantum Hierarchical Deterministic Wallets
  Status: Draft
  Type: Standards Track
  Created: 2026-02-17
  Requires: BIP-39, BIP-43, BIP-360, FIPS 205
```

## Abstract

A PQC-native standard for deterministic derivation of SLH-DSA (FIPS 205)
keypairs from a BIP-39 mnemonic. Unlike a simple "BIP-32 with different
HMAC key," this standard uses the native cryptographic primitives of
SLH-DSA throughout the derivation chain.

## PQC-Native Design

This standard makes three deliberate departures from BIP-32:

### 1. SHAKE-256 as the Core KDF

BIP-32 uses HMAC-SHA512 for all key derivation. BIP-PQC32 uses **SHAKE-256**,
the native extendable-output function (XOF) of SLH-DSA-SHAKE-128s.

SLH-DSA-SHAKE-128s uses SHAKE-256 internally for every hash operation
(FIPS 205, Section 11.1):

```
Hmsg:   SHAKE-256(R || PK.seed || PK.root || M)      — message hashing
PRF:    SHAKE-256(PK.seed || ADRS || SK.seed)         — secret value generation
PRFmsg: SHAKE-256(SK.prf || opt_rand || M)            — randomized signing
F/H/T:  SHAKE-256(PK.seed || ADRS || M)               — tree hashing
```

Using SHAKE-256 for key derivation maintains algorithmic consistency. The
derivation chain speaks the same cryptographic language as the signature scheme.

### 2. Direct FIPS 205 Component Derivation

BIP-32 treats keys as opaque 32-byte values. BIP-PQC32 derives the named
FIPS 205 key components individually:

```
SHAKE-256 derivation → SK.seed (16B) || SK.prf (16B) || PK.seed (16B)
                                         ↓
                        WASM hypertree construction
                                         ↓
                                    PK.root (16B)
```

Each component has a specific role in SLH-DSA:

| Component | Size | Role |
|---|---|---|
| SK.seed | n bytes (16) | Seed for WOTS+ and FORS secret generation |
| SK.prf | n bytes (16) | PRF key for randomized message hashing |
| PK.seed | n bytes (16) | Public seed for hash tree domain separation |
| PK.root | n bytes (16) | Root of top-level XMSS Merkle tree (computed) |

**PK.root cannot be derived from SHAKE-256 alone.** It requires full hypertree
construction — this is fundamental to hash-based signatures.

### 3. Algorithm ID in Serialization

BIP-32 xprv is implicitly secp256k1. BIP-PQC32 xprv includes an explicit
algorithm ID byte, making the format self-describing and extensible:

```
Algorithm 0x01 = SLH-DSA-SHAKE-128s (n=16)
Algorithm 0x02 = SLH-DSA-SHAKE-128f (future)
Algorithm 0x03 = SLH-DSA-SHAKE-256s (future)
Algorithm 0x10 = ML-DSA-44 (future)
```

## Specification

### 1. SLH-DSA Parameter Set

All constants from FIPS 205 Table 1 for SLH-DSA-SHAKE-128s:

```
n  = 16      Security parameter (bytes per component)
h  = 63      Total hypertree height
d  = 7       Number of hypertree layers
hp = 9       Individual XMSS tree height (h/d)
a  = 12      FORS parameter
k  = 14      Number of FORS trees
SK = 4n = 64 bytes
PK = 2n = 32 bytes
Sig = 7856 bytes
```

### 2. Master Key Generation

From a BIP-39 seed `S` (64 bytes):

```
I = HMAC-SHA512(Key = "Bitcoin PQC seed", Data = S)

masterSeed  = I[0..31]    (32 bytes)
masterChain = I[32..63]   (32 bytes)
```

This single HMAC-SHA512 exists solely for BIP-39 compatibility.
All subsequent operations use SHAKE-256.

### 3. SHAKE-256 Component Derivation

At each tree level, SLH-DSA components are derived:

```
input  = "SLH-DSA-SHAKE-128s:derive" || secretSeed(32) || chainCode(32)
output = SHAKE-256(input, outputLength = 3n)

SK.seed = output[ 0 .. n-1 ]     (16 bytes)
SK.prf  = output[ n .. 2n-1]     (16 bytes)
PK.seed = output[2n .. 3n-1]     (16 bytes)
```

### 4. SHAKE-256 Child Derivation

Child key derivation (replaces BIP-32's HMAC-SHA512):

```
input  = "SLH-DSA-SHAKE-128s:child" || parentSeed(32) || parentChain(32) || ser32(index)
output = SHAKE-256(input, outputLength = 64)

childSeed  = output[ 0..31]
childChain = output[32..63]
```

Then derive components for the child: Section 3 with (childSeed, childChain).

### 5. WASM Key Generation

At the leaf node, construct the full SLH-DSA keypair:

```
core = SK.seed(16) || SK.prf(16) || PK.seed(16)        → 48 bytes
pad  = SHAKE-256("SLH-DSA-SHAKE-128s:pad" || core || chainCode, 80)
wasmInput = core || pad                                  → 128 bytes

keypair = slh_dsa_shake_128s_keygen(wasmInput)

PK.root = keypair.secretKey[48..63]    ← computed by hypertree
```

### 6. Derivation Path

```
m / purpose' / coin_type' / account' / change' / address_index'
m / 360'     / 2121'      / 0'       / 0'      / 0'
```

ALL levels are hardened. Non-hardened derivation MUST be rejected.

### 7. Extended Private Key Serialization

Format (79 bytes):

```
┌──────────┬──────────┬───────┬──────────┬───────────┬──────────┬──────────────────┐
│ version  │ alg. ID  │ depth │ par. FP  │ child idx │ chain    │ 0x00 + secretSeed│
│ 4 bytes  │ 1 byte   │ 1B    │ 4B       │ 4B        │ 32B      │ 33B              │
└──────────┴──────────┴───────┴──────────┴───────────┴──────────┴──────────────────┘
 79 bytes → Base58Check → "pqprv..."
```

| Field | Offset | Size | Description |
|---|---|---|---|
| version | 0 | 4 | `0x04C5FA3E` (mainnet) or `0x04C5EDAE` (testnet) |
| algorithmId | 4 | 1 | `0x01` = SLH-DSA-SHAKE-128s |
| depth | 5 | 1 | Tree depth (0 = master) |
| parentFingerprint | 6 | 4 | HASH160(parent.secretSeed)[0..3] |
| childIndex | 10 | 4 | Index with hardened flag (OR 0x80000000) |
| chainCode | 14 | 32 | Chain code |
| padding | 46 | 1 | 0x00 |
| secretSeed | 47 | 32 | Derivation secret seed |

On deserialization, the algorithm ID determines:
- SHAKE-256 domain tags for component re-derivation
- Component sizes (n=16 for 0x01)
- WASM algorithm for keypair generation

## Comparison: BIP-32 vs BIP-PQC32

| Aspect | BIP-32 (ECDSA) | BIP-PQC32 (SLH-DSA) |
|---|---|---|
| **KDF** | HMAC-SHA512 | **SHAKE-256** (native to SLH-DSA) |
| **Key components** | Opaque 32-byte scalar | **SK.seed, SK.prf, PK.seed** (FIPS 205) |
| **Child derivation** | HMAC-SHA512 + EC point add | **SHAKE-256** (no algebra) |
| **Algorithm in serialization** | Implicit (secp256k1) | **Explicit algorithm ID byte** |
| **xpub** | Yes (EC point math) | **No** (no group structure) |
| **Non-hardened** | Yes | **No** (impossible for hash-based) |
| **PK computation** | Scalar × Generator | **Hypertree construction** |
| **Serialization** | 78 bytes | **79 bytes** (+1 for algorithm ID) |

## Security Considerations

### SHAKE-256 Security

SHAKE-256 provides 256-bit security against preimage and 128-bit against
collision (same as SHA-256). For SLH-DSA-SHAKE-128s targeting NIST level 1
(128-bit security), SHAKE-256 is more than sufficient.

### Domain Separation

Every SHAKE-256 call includes the full algorithm name as a prefix:
- `"SLH-DSA-SHAKE-128s:derive"` — component derivation
- `"SLH-DSA-SHAKE-128s:child"` — child key derivation
- `"SLH-DSA-SHAKE-128s:pad"` — WASM input padding

This prevents cross-algorithm collisions if future schemes are added.

### Algorithm Agility

The algorithm ID in the xprv format enables future PQC schemes without
format changes. A decoder reads the ID, looks up the parameter set, and
uses the correct SHAKE-256 domain tags and component sizes.

## References

- [FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf): SLH-DSA Standard
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): Mnemonic Codes
- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki): HD Wallets
- [BIP-360](https://bip360.org/bip360.html): P2TSH / P2MR
- [libbitcoinpqc](https://github.com/cryptoquick/libbitcoinpqc): BIP-360 PQC Library