/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  pqc32 — Post-Quantum HD Wallet Derivation for SLH-DSA (FIPS 205)
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Pure library. No wallet code. No chain-specific logic.
 *  Use it like bip39 or bip32 — import into any wallet.
 *
 *  Dependencies: bip39, node:crypto
 *  Peer dependency: any FIPS 205 keygen implementation (injected)
 *
 *  PQC-native:
 *    • SHAKE-256 as the core KDF (native XOF of SLH-DSA-SHAKE)
 *    • Derives FIPS 205 components: SK.seed, SK.prf, PK.seed
 *    • Algorithm ID in xprv serialization
 *    • All derivation is hardened (no xpub, no public derivation)
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 */

import * as bip39 from "bip39"
import * as crypto from "crypto"
import {
  SLHDSAParamSet,
  SLHDSAComponents,
  PQC32Keypair,
  PQC32ExtendedKey,
  PQC32DerivedKey,
  KeygenFunction,
} from "./types"
import { DEFAULT_ALGORITHM, ALGORITHM_REGISTRY } from "./params"

// Re-export everything consumers need
export * from "./types"
export * from "./params"

// ═══════════════════════════════════════════════════════════════════════════════
//  SHAKE-256 DERIVATION (PQC-NATIVE)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Derive SLH-DSA key components using SHAKE-256.
 *
 * SHAKE-256 is the native XOF of SLH-DSA-SHAKE (FIPS 205 §11.1).
 * Using it here maintains algorithmic consistency with the signature scheme.
 *
 * ```
 * input  = "{algorithmName}:derive" || seed(32) || context(32)
 * output = SHAKE-256(input, 3n)
 *
 * SK.seed = output[ 0  .. n-1 ]
 * SK.prf  = output[ n  .. 2n-1]
 * PK.seed = output[ 2n .. 3n-1]
 * ```
 */
export const deriveComponents = (
  seed: Buffer,
  context: Buffer,
  params: SLHDSAParamSet = DEFAULT_ALGORITHM,
): SLHDSAComponents => {
  const n = params.n
  const tag = Buffer.from(`${params.name}:derive`)
  const input = Buffer.concat([tag, seed, context])
  const output = crypto
    .createHash("shake256", { outputLength: 3 * n })
    .update(input)
    .digest()

  return {
    skSeed: Buffer.from(output.subarray(0, n)),
    skPrf: Buffer.from(output.subarray(n, 2 * n)),
    pkSeed: Buffer.from(output.subarray(2 * n, 3 * n)),
    pkRoot: null,
  }
}

/**
 * SHAKE-256 child key derivation.
 *
 * Replaces BIP-32's HMAC-SHA512 child derivation.
 *
 * ```
 * input  = "{algorithmName}:child" || parentSeed(32) || parentChain(32) || ser32(index)
 * output = SHAKE-256(input, 64)
 *
 * childSeed  = output[0..31]
 * childChain = output[32..63]
 * ```
 */
const deriveChildRaw = (
  parentSeed: Buffer,
  parentChain: Buffer,
  index: number,
  params: SLHDSAParamSet,
): { childSeed: Buffer; childChain: Buffer } => {
  const tag = Buffer.from(`${params.name}:child`)
  const idxBuf = Buffer.alloc(4)
  idxBuf.writeUInt32BE(index, 0)
  const input = Buffer.concat([tag, parentSeed, parentChain, idxBuf])
  const output = crypto
    .createHash("shake256", { outputLength: 64 })
    .update(input)
    .digest()

  return {
    childSeed: Buffer.from(output.subarray(0, 32)),
    childChain: Buffer.from(output.subarray(32, 64)),
  }
}

/**
 * Build keygen input from FIPS 205 components.
 *
 * Core = SK.seed || SK.prf || PK.seed (3n bytes)
 * Pad  = SHAKE-256 deterministic padding to reach wasmInputBytes
 */
export const buildKeygenInput = (
  components: SLHDSAComponents,
  chainCode: Buffer,
  params: SLHDSAParamSet = DEFAULT_ALGORITHM,
  totalBytes: number = 128,
): Uint8Array => {
  const n = params.n
  const core = Buffer.concat([components.skSeed, components.skPrf, components.pkSeed])
  if (core.length !== 3 * n) {
    throw new Error(`Component size mismatch: expected ${3 * n}, got ${core.length}`)
  }

  const padSize = totalBytes - core.length
  if (padSize <= 0) {
    // Core already meets or exceeds required size
    const result = new Uint8Array(totalBytes)
    result.set(new Uint8Array(core.subarray(0, totalBytes)), 0)
    return result
  }

  const padInput = Buffer.concat([Buffer.from(`${params.name}:pad`), core, chainCode])
  const pad = crypto
    .createHash("shake256", { outputLength: padSize })
    .update(padInput)
    .digest()

  const result = new Uint8Array(totalBytes)
  result.set(new Uint8Array(core), 0)
  result.set(new Uint8Array(pad), core.length)
  return result
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HD TREE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create master extended key from BIP-39 mnemonic.
 *
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param passphrase - Optional BIP-39 passphrase
 * @param params - SLH-DSA parameter set (default: SHAKE-128s)
 */
export const fromMnemonic = (
  mnemonic: string,
  passphrase: string = "",
  params: SLHDSAParamSet = DEFAULT_ALGORITHM,
): PQC32ExtendedKey => {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error("Invalid BIP-39 mnemonic")
  }
  return fromSeed(bip39.mnemonicToSeedSync(mnemonic, passphrase), params)
}

/**
 * Create master extended key from raw 64-byte BIP-39 seed.
 *
 * The single HMAC-SHA512 here is for BIP-39 compatibility only.
 * All subsequent derivation uses SHAKE-256.
 */
export const fromSeed = (
  seed: Buffer | Uint8Array,
  params: SLHDSAParamSet = DEFAULT_ALGORITHM,
): PQC32ExtendedKey => {
  if (seed.length !== 64) {
    throw new Error(`Seed must be 64 bytes, got ${seed.length}`)
  }

  // Single HMAC-SHA512 for BIP-39 compatibility
  const I = crypto.createHmac("sha512", "Bitcoin PQC seed").update(seed).digest()
  const secretSeed = Buffer.from(I.subarray(0, 32))
  const chainCode = Buffer.from(I.subarray(32, 64))

  // SHAKE-256 component derivation
  const components = deriveComponents(secretSeed, chainCode, params)

  return {
    secretSeed,
    chainCode,
    depth: 0,
    parentFingerprint: Buffer.alloc(4, 0x00),
    index: 0,
    path: "m",
    algorithmId: params.algorithmId,
    components,
  }
}

/**
 * Derive hardened child key using SHAKE-256.
 */
export const deriveHardenedChild = (
  parent: PQC32ExtendedKey,
  index: number,
): PQC32ExtendedKey => {
  if (!Number.isInteger(index) || index < 0 || index > 0x7fffffff) {
    throw new Error(`Index must be in [0, 2^31 - 1], got ${index}`)
  }

  const params = ALGORITHM_REGISTRY[parent.algorithmId]
  if (!params) throw new Error(`Unknown algorithm: 0x${parent.algorithmId.toString(16)}`)

  // Parent fingerprint
  const sha = crypto.createHash("sha256").update(parent.secretSeed).digest()
  const ripe = crypto.createHash("ripemd160").update(sha).digest()
  const fp = Buffer.from(ripe.subarray(0, 4))

  // SHAKE-256 child derivation
  const { childSeed, childChain } = deriveChildRaw(
    parent.secretSeed,
    parent.chainCode,
    index,
    params,
  )

  // SHAKE-256 component derivation
  const components = deriveComponents(childSeed, childChain, params)

  return {
    secretSeed: childSeed,
    chainCode: childChain,
    depth: parent.depth + 1,
    parentFingerprint: fp,
    index,
    path: `${parent.path}/${index}'`,
    algorithmId: parent.algorithmId,
    components,
  }
}

/**
 * Derive from full path. ALL levels must be hardened.
 *
 * @example
 * ```ts
 * const master = pqc32.fromMnemonic(mnemonic)
 * const leaf = pqc32.derivePath(master, "m/360'/2121'/0'/0'/0'")
 * ```
 */
export const derivePath = (
  master: PQC32ExtendedKey,
  path: string,
): PQC32ExtendedKey => {
  const segments = path.replace(/^m\/?/, "").split("/").filter(Boolean)
  let node = master
  for (const seg of segments) {
    if (!seg.endsWith("'")) {
      throw new Error(
        `PQC32: All derivation must be hardened. Got "${seg}" in "${path}".`,
      )
    }
    const idx = parseInt(seg.replace("'", ""), 10)
    if (isNaN(idx)) throw new Error(`Invalid path segment: "${seg}"`)
    node = deriveHardenedChild(node, idx)
  }
  return node
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KEY GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate SLH-DSA keypair from a derived node.
 *
 * The keygen function is INJECTED — this lib does not depend on any
 * specific WASM/native implementation. Pass your own:
 *
 * @example
 * ```ts
 * import { Algorithm, bitcoinpqc } from "@jbride/bitcoinpqc-wasm"
 *
 * const keygen = (seed: Uint8Array) =>
 *   bitcoinpqc.generateKeypair(Algorithm.SLH_DSA_SHAKE_128S, seed)
 *
 * const result = await pqc32.generateKeypair(leaf, keygen)
 * ```
 *
 * Or with libbitcoinpqc:
 * ```ts
 * import { Algorithm, generateKeyPair } from "bitcoinpqc"
 *
 * const keygen = (seed: Uint8Array) =>
 *   generateKeyPair(Algorithm.SLH_DSA_SHAKE_128S, seed)
 *
 * const result = await pqc32.generateKeypair(leaf, keygen)
 * ```
 */
export const generateKeypair = async (
  node: PQC32ExtendedKey,
  keygen: KeygenFunction,
  wasmInputBytes: number = 128,
): Promise<PQC32DerivedKey> => {
  const params = ALGORITHM_REGISTRY[node.algorithmId]
  if (!params) throw new Error(`Unknown algorithm: 0x${node.algorithmId.toString(16)}`)

  // Build deterministic input from FIPS 205 components
  const input = buildKeygenInput(node.components, node.chainCode, params, wasmInputBytes)

  // Call injected keygen (WASM, native, etc.)
  const raw = await keygen(input)
  input.fill(0)

  const secretKeyHex = Buffer.from(raw.secretKey).toString("hex")
  const publicKeyHex = Buffer.from(raw.publicKey).toString("hex")

  // Extract PK.root from generated key
  const n = params.n
  const pkRoot = Buffer.from(raw.secretKey.slice(3 * n, 4 * n))

  return {
    keypair: {
      secretKey: raw.secretKey,
      publicKey: raw.publicKey,
      secretKeyHex,
      publicKeyHex,
    },
    components: {
      skSeed: Buffer.from(node.components.skSeed),
      skPrf: Buffer.from(node.components.skPrf),
      pkSeed: Buffer.from(node.components.pkSeed),
      pkRoot,
    },
    path: node.path,
    depth: node.depth,
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  XPRV SERIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

export const XPRV_VERSION = {
  /** Produces Base58 prefix "pqrv" (pq-priv) */
  MAINNET: 0x330f1300,
  /** Produces Base58 prefix "pqts" (pq-test) */
  TESTNET: 0x330f3b60,
} as const

/**
 * Serialize extended key to Base58Check string.
 *
 * Format (79 bytes):
 * ```
 * [version 4B] [algID 1B] [depth 1B] [parentFP 4B] [index 4B] [chain 32B] [0x00+seed 33B]
 * ```
 */
export const serializeXprv = (
  key: PQC32ExtendedKey,
  network: "mainnet" | "testnet" = "mainnet",
): string => {
  const ver = network === "testnet" ? XPRV_VERSION.TESTNET : XPRV_VERSION.MAINNET
  const buf = Buffer.alloc(79)

  buf.writeUInt32BE(ver, 0)
  buf.writeUInt8(key.algorithmId, 4)
  buf.writeUInt8(key.depth, 5)
  key.parentFingerprint.copy(buf, 6)
  buf.writeUInt32BE(key.depth === 0 ? 0 : (key.index | 0x80000000) >>> 0, 10)
  key.chainCode.copy(buf, 14)
  buf[46] = 0x00
  key.secretSeed.copy(buf, 47)

  return base58CheckEncode(buf)
}

/**
 * Deserialize xprv string back to extended key.
 * Re-derives FIPS 205 components via SHAKE-256 using the algorithm ID.
 */
export const deserializeXprv = (str: string): PQC32ExtendedKey => {
  const buf = base58CheckDecode(str)
  if (buf.length !== 79) throw new Error(`Invalid xprv: expected 79 bytes, got ${buf.length}`)

  const version = buf.readUInt32BE(0)
  if (version !== XPRV_VERSION.MAINNET && version !== XPRV_VERSION.TESTNET) {
    throw new Error(`Invalid xprv version: 0x${version.toString(16).padStart(8, "0")}`)
  }

  const algorithmId = buf.readUInt8(4)
  const params = ALGORITHM_REGISTRY[algorithmId]
  if (!params) {
    const known = Object.entries(ALGORITHM_REGISTRY)
      .map(([id, p]) => `0x${Number(id).toString(16)}=${p.name}`)
      .join(", ")
    throw new Error(`Unknown algorithm: 0x${algorithmId.toString(16)}. Known: ${known}`)
  }

  const depth = buf.readUInt8(5)
  const parentFingerprint = Buffer.from(buf.subarray(6, 10))
  const rawIndex = buf.readUInt32BE(10)
  const chainCode = Buffer.from(buf.subarray(14, 46))
  if (buf[46] !== 0x00) throw new Error("Invalid xprv padding")
  const secretSeed = Buffer.from(buf.subarray(47, 79))

  const index = depth === 0 ? 0 : rawIndex & 0x7fffffff

  // Re-derive components via SHAKE-256
  const components = deriveComponents(secretSeed, chainCode, params)

  return {
    secretSeed,
    chainCode,
    depth,
    parentFingerprint,
    index,
    path: depth === 0 ? "m" : `.../${index}'`,
    algorithmId,
    components,
  }
}

/** Validate xprv string */
export const isValidXprv = (str: string): boolean => {
  try { deserializeXprv(str); return true } catch { return false }
}

/** Get network from xprv */
export const getXprvNetwork = (str: string): "mainnet" | "testnet" => {
  const buf = base58CheckDecode(str)
  return buf.readUInt32BE(0) === XPRV_VERSION.TESTNET ? "testnet" : "mainnet"
}

/** Get algorithm name from xprv */
export const getXprvAlgorithm = (str: string): string => {
  const buf = base58CheckDecode(str)
  const id = buf.readUInt8(4)
  return ALGORITHM_REGISTRY[id]?.name ?? `Unknown(0x${id.toString(16)})`
}

// ═══════════════════════════════════════════════════════════════════════════════
//  UTILITY
// ═══════════════════════════════════════════════════════════════════════════════

/** Compute key fingerprint: HASH160(secretSeed)[0..3] */
export const fingerprint = (key: PQC32ExtendedKey): Buffer => {
  const sha = crypto.createHash("sha256").update(key.secretSeed).digest()
  const ripe = crypto.createHash("ripemd160").update(sha).digest()
  return Buffer.from(ripe.subarray(0, 4))
}

/** Zero out sensitive buffers on an extended key */
export const wipe = (key: PQC32ExtendedKey): void => {
  key.secretSeed.fill(0)
  key.chainCode.fill(0)
  key.components.skSeed.fill(0)
  key.components.skPrf.fill(0)
  key.components.pkSeed.fill(0)
  if (key.components.pkRoot) key.components.pkRoot.fill(0)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BASE58CHECK (INTERNAL)
// ═══════════════════════════════════════════════════════════════════════════════

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

const base58CheckEncode = (payload: Buffer): string => {
  const cs = crypto.createHash("sha256").update(
    crypto.createHash("sha256").update(payload).digest(),
  ).digest().subarray(0, 4)
  return base58Encode(Buffer.concat([payload, cs]))
}

const base58CheckDecode = (str: string): Buffer => {
  const data = base58Decode(str)
  if (data.length < 4) throw new Error("Base58Check: too short")
  const payload = data.subarray(0, data.length - 4)
  const cs = data.subarray(data.length - 4)
  const exp = crypto.createHash("sha256").update(
    crypto.createHash("sha256").update(payload).digest(),
  ).digest().subarray(0, 4)
  if (!cs.equals(exp)) throw new Error("Base58Check: invalid checksum")
  return Buffer.from(payload)
}

const base58Encode = (data: Buffer): string => {
  let z = 0
  for (let i = 0; i < data.length && data[i] === 0; i++) z++
  const d: number[] = []
  let n = BigInt("0x" + (data.length > 0 ? data.toString("hex") : "0"))
  while (n > 0n) { d.push(Number(n % 58n)); n /= 58n }
  let r = "1".repeat(z)
  for (let i = d.length - 1; i >= 0; i--) {
    r += B58.charAt(d[i]!)
  }
  return r
}

const base58Decode = (str: string): Buffer => {
  let z = 0
  for (let i = 0; i < str.length && str[i] === "1"; i++) z++
  let n = 0n
  for (const c of str) {
    const idx = B58.indexOf(c)
    if (idx === -1) throw new Error(`Invalid Base58: "${c}"`)
    n = n * 58n + BigInt(idx)
  }
  let h = n.toString(16)
  if (h.length % 2) h = "0" + h
  return Buffer.concat([Buffer.alloc(z), Buffer.from(h, "hex")])
}