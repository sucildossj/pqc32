/**
 * BIP-PQC32 Type Definitions
 *
 * Pure types — no external dependencies.
 */

// ─── FIPS 205 Parameter Set ─────────────────────────────────────────────────

export interface SLHDSAParamSet {
  /** Full algorithm name per FIPS 205 */
  readonly name: string
  /** n — security parameter in bytes */
  readonly n: number
  /** NIST security level */
  readonly securityLevel: number
  /** Secret key size = 4n */
  readonly secretKeyBytes: number
  /** Public key size = 2n */
  readonly publicKeyBytes: number
  /** Signature size */
  readonly signatureBytes: number
  /** h — total hypertree height */
  readonly h: number
  /** d — hypertree layers */
  readonly d: number
  /** hp — individual tree height (h/d) */
  readonly hp: number
  /** a — FORS parameter */
  readonly a: number
  /** k — number of FORS trees */
  readonly k: number
  /** Keygen randomness = 3n */
  readonly keygenRandomnessBytes: number
  /** Algorithm ID for xprv serialization */
  readonly algorithmId: number
}

// ─── FIPS 205 Key Components ────────────────────────────────────────────────

export interface SLHDSAComponents {
  /** SK.seed — WOTS+ / FORS secret generation seed (n bytes) */
  skSeed: Buffer
  /** SK.prf — PRF key for randomized message hashing (n bytes) */
  skPrf: Buffer
  /** PK.seed — public seed for hash tree addressing (n bytes) */
  pkSeed: Buffer
  /** PK.root — top XMSS Merkle root (n bytes). null before keygen. */
  pkRoot: Buffer | null
}

// ─── Keypair ────────────────────────────────────────────────────────────────

export interface PQC32Keypair {
  secretKey: Uint8Array
  publicKey: Uint8Array
  secretKeyHex: string
  publicKeyHex: string
}

// ─── Extended Key ───────────────────────────────────────────────────────────

export interface PQC32ExtendedKey {
  /** 32-byte derivation seed */
  secretSeed: Buffer
  /** 32-byte chain code */
  chainCode: Buffer
  /** Tree depth (0 = master) */
  depth: number
  /** Parent fingerprint: HASH160(parent.secretSeed)[0..3] */
  parentFingerprint: Buffer
  /** Child index */
  index: number
  /** Derivation path */
  path: string
  /** Algorithm ID (0x01 = SLH-DSA-SHAKE-128s) */
  algorithmId: number
  /** FIPS 205 components derived via SHAKE-256 */
  components: SLHDSAComponents
}

// ─── Derived Key Result ─────────────────────────────────────────────────────

export interface PQC32DerivedKey {
  keypair: PQC32Keypair
  components: SLHDSAComponents
  path: string
  depth: number
}

// ─── Keygen Function (injected by caller) ───────────────────────────────────

/**
 * Function signature for SLH-DSA key generation.
 *
 * The PQC32 lib does NOT depend on any WASM library directly.
 * Instead, the caller injects a keygen function that matches this signature.
 *
 * This allows the lib to work with:
 *   - @jbride/bitcoinpqc-wasm
 *   - libbitcoinpqc (Rust/Python/Node bindings)
 *   - Any future FIPS 205 implementation
 *
 * @param seed - Deterministic seed bytes (wasmInputBytes length)
 * @returns Raw keypair bytes
 */
export type KeygenFunction = (
  seed: Uint8Array,
) => { secretKey: Uint8Array; publicKey: Uint8Array } | Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }>