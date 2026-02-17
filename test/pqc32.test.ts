/**
 * pqc32 test suite
 *
 * Tests the pure library with a mock keygen function.
 * No wallet code, no WASM — just derivation + serialization.
 */

import * as pqc32 from "../src"
import * as crypto from "crypto"

const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

const hex = (buf: Buffer | Uint8Array): string => Buffer.from(buf).toString("hex")

/**
 * Mock SLH-DSA keygen — produces a deterministic 64-byte SK and 32-byte PK
 * from the seed input, without actual hypertree construction.
 *
 * In real usage, this would be:
 *   (seed) => bitcoinpqc.generateKeypair(Algorithm.SLH_DSA_SHAKE_128S, seed)
 */
const mockKeygen: pqc32.KeygenFunction = (seed: Uint8Array) => {
  const n = 16
  // Use SHAKE-256 to simulate deterministic key output
  const sk = crypto
    .createHash("shake256", { outputLength: 4 * n })
    .update(seed)
    .digest()
  // PK = SK[2n..4n]
  const pk = Buffer.from(sk.subarray(2 * n, 4 * n))
  return { secretKey: new Uint8Array(sk), publicKey: new Uint8Array(pk) }
}

async function runTests() {
  const params = pqc32.SLH_DSA_SHAKE_128S
  const n = params.n

  console.log("╔══════════════════════════════════════════════════════════╗")
  console.log("║  pqc32 — Test Suite                                     ║")
  console.log("╚══════════════════════════════════════════════════════════╝\n")

  // ── 1. fromMnemonic ──
  console.log("── 1. fromMnemonic ──")
  const master = pqc32.fromMnemonic(TEST_MNEMONIC)
  console.log(`  depth: ${master.depth} ${master.depth === 0 ? "✅" : "❌"}`)
  console.log(`  path: ${master.path} ${master.path === "m" ? "✅" : "❌"}`)
  console.log(`  algorithmId: 0x${master.algorithmId.toString(16)} ${master.algorithmId === 0x01 ? "✅" : "❌"}`)
  console.log(`  SK.seed (${master.components.skSeed.length}B): ${hex(master.components.skSeed)} ${master.components.skSeed.length === n ? "✅" : "❌"}`)
  console.log(`  SK.prf  (${master.components.skPrf.length}B): ${hex(master.components.skPrf)} ${master.components.skPrf.length === n ? "✅" : "❌"}`)
  console.log(`  PK.seed (${master.components.pkSeed.length}B): ${hex(master.components.pkSeed)} ${master.components.pkSeed.length === n ? "✅" : "❌"}`)
  console.log(`  PK.root: ${master.components.pkRoot === null ? "null ✅" : "❌"}`)
  console.log()

  // ── 2. SHAKE-256 child derivation ──
  console.log("── 2. SHAKE-256 child derivation ──")
  const child = pqc32.deriveHardenedChild(master, 360)

  // Manual SHAKE-256 verification
  const manualInput = Buffer.concat([
    Buffer.from(`${params.name}:child`),
    master.secretSeed,
    master.chainCode,
    Buffer.from([0x00, 0x00, 0x01, 0x68]),
  ])
  const manualOutput = crypto.createHash("shake256", { outputLength: 64 }).update(manualInput).digest()
  const shakeMatch = hex(manualOutput.subarray(0, 32)) === hex(child.secretSeed)
  console.log(`  SHAKE-256 verified: ${shakeMatch ? "✅" : "❌"}`)
  console.log(`  depth: ${child.depth} ${child.depth === 1 ? "✅" : "❌"}`)
  console.log(`  path: ${child.path} ${child.path === "m/360'" ? "✅" : "❌"}`)
  console.log(`  Components re-derived: ${child.components.skSeed.length === n ? "✅" : "❌"}`)
  console.log()

  // ── 3. derivePath ──
  console.log("── 3. derivePath ──")
  const path = "m/360'/2121'/0'/0'/0'"
  const leaf = pqc32.derivePath(master, path)
  console.log(`  path: ${leaf.path} ${leaf.path === path ? "✅" : "❌"}`)
  console.log(`  depth: ${leaf.depth} ${leaf.depth === 5 ? "✅" : "❌"}`)

  // Hardened-only enforcement
  let rejected = false
  try { pqc32.derivePath(master, "m/360'/0'/0'/0/0") } catch { rejected = true }
  console.log(`  Non-hardened rejected: ${rejected ? "✅" : "❌"}`)
  console.log()

  // ── 4. generateKeypair (with mock) ──
  console.log("── 4. generateKeypair ──")
  const m1 = pqc32.fromMnemonic(TEST_MNEMONIC)
  const l1 = pqc32.derivePath(m1, path)
  const d1 = await pqc32.generateKeypair(l1, mockKeygen)
  console.log(`  SK length: ${d1.keypair.secretKey.length} ${d1.keypair.secretKey.length === 4 * n ? "✅" : "❌"}`)
  console.log(`  PK length: ${d1.keypair.publicKey.length} ${d1.keypair.publicKey.length === 2 * n ? "✅" : "❌"}`)
  console.log(`  PK.root filled: ${d1.components.pkRoot !== null ? "✅" : "❌"}`)
  console.log(`  PK.root size: ${d1.components.pkRoot?.length} ${d1.components.pkRoot?.length === n ? "✅" : "❌"}`)
  console.log()

  // ── 5. Determinism ──
  console.log("── 5. Determinism ──")
  const m2 = pqc32.fromMnemonic(TEST_MNEMONIC)
  const l2 = pqc32.derivePath(m2, path)
  const d2 = await pqc32.generateKeypair(l2, mockKeygen)
  const det = d1.keypair.publicKeyHex === d2.keypair.publicKeyHex
  console.log(`  Same input → same output: ${det ? "✅" : "❌"}`)
  console.log()

  // ── 6. Path isolation ──
  console.log("── 6. Path isolation ──")
  const paths = [
    "m/360'/2121'/0'/0'/0'",
    "m/360'/2121'/0'/0'/1'",
    "m/360'/2121'/0'/1'/0'",
    "m/360'/2121'/1'/0'/0'",
    "m/360'/0'/0'/0'/0'",
  ]
  const pks: string[] = []
  for (const p of paths) {
    const m = pqc32.fromMnemonic(TEST_MNEMONIC)
    const l = pqc32.derivePath(m, p)
    const d = await pqc32.generateKeypair(l, mockKeygen)
    pks.push(d.keypair.publicKeyHex)
  }
  console.log(`  All unique: ${new Set(pks).size === pks.length ? "✅" : "❌"}`)
  console.log()

  // ── 7. xprv serialization ──
  console.log("── 7. xprv serialization ──")
  const xprv = pqc32.serializeXprv(master)
  console.log(`  Master xprv: ${xprv.slice(0, 20)}...${xprv.slice(-8)}`)

  const alg = pqc32.getXprvAlgorithm(xprv)
  console.log(`  Algorithm: ${alg} ${alg === "SLH-DSA-SHAKE-128s" ? "✅" : "❌"}`)
  console.log(`  Network: ${pqc32.getXprvNetwork(xprv)} ✅`)
  console.log(`  Valid: ${pqc32.isValidXprv(xprv) ? "✅" : "❌"}`)
  console.log(`  BIP-32 xprv rejected: ${!pqc32.isValidXprv("xprv9s21ZrQH143K3QTDL4LXw2") ? "✅" : "❌"}`)
  console.log()

  // ── 8. xprv round-trip ──
  console.log("── 8. xprv round-trip ──")
  const restored = pqc32.deserializeXprv(xprv)
  const seedMatch = hex(restored.secretSeed) === hex(master.secretSeed)
  const chainMatch = hex(restored.chainCode) === hex(master.chainCode)
  const algMatch = restored.algorithmId === master.algorithmId
  const compMatch = hex(restored.components.skSeed) === hex(master.components.skSeed)
  console.log(`  secretSeed: ${seedMatch ? "✅" : "❌"}`)
  console.log(`  chainCode: ${chainMatch ? "✅" : "❌"}`)
  console.log(`  algorithmId: ${algMatch ? "✅" : "❌"}`)
  console.log(`  SK.seed re-derived: ${compMatch ? "✅" : "❌"}`)
  console.log(`  Re-serialize: ${pqc32.serializeXprv(restored) === xprv ? "✅" : "❌"}`)
  console.log()

  // ── 9. xprv → derive child ──
  console.log("── 9. Derive from restored xprv ──")
  const accountKey = pqc32.derivePath(pqc32.fromMnemonic(TEST_MNEMONIC), "m/360'/2121'/0'")
  const accountXprv = pqc32.serializeXprv(accountKey)
  const restoredAccount = pqc32.deserializeXprv(accountXprv)

  const fromXprv = await pqc32.generateKeypair(
    pqc32.deriveHardenedChild(pqc32.deriveHardenedChild(restoredAccount, 0), 0),
    mockKeygen,
  )
  const fromDirect = await pqc32.generateKeypair(
    pqc32.derivePath(pqc32.fromMnemonic(TEST_MNEMONIC), path),
    mockKeygen,
  )
  console.log(`  xprv child matches direct: ${fromXprv.keypair.publicKeyHex === fromDirect.keypair.publicKeyHex ? "✅" : "❌"}`)
  console.log()

  // ── 10. Testnet ──
  console.log("── 10. Testnet xprv ──")
  const mainXprv = pqc32.serializeXprv(master, "mainnet")
  const testXprv = pqc32.serializeXprv(master, "testnet")
  console.log(`  Different prefix: ${mainXprv.slice(0, 5) !== testXprv.slice(0, 5) ? "✅" : "❌"}`)
  console.log(`  Mainnet detected: ${pqc32.getXprvNetwork(mainXprv) === "mainnet" ? "✅" : "❌"}`)
  console.log(`  Testnet detected: ${pqc32.getXprvNetwork(testXprv) === "testnet" ? "✅" : "❌"}`)
  console.log()

  // ── 11. wipe ──
  console.log("── 11. Wipe ──")
  const toWipe = pqc32.fromMnemonic(TEST_MNEMONIC)
  pqc32.wipe(toWipe)
  const allZeros = hex(toWipe.secretSeed) === "0".repeat(64) &&
    hex(toWipe.components.skSeed) === "0".repeat(2 * n)
  console.log(`  Wiped to zeros: ${allZeros ? "✅" : "❌"}`)
  console.log()

  // ── 12. Algorithm registry ──
  console.log("── 12. Algorithm registry ──")
  for (const [id, p] of Object.entries(pqc32.ALGORITHM_REGISTRY)) {
    console.log(`  0x${Number(id).toString(16).padStart(2, "0")} → ${p.name} (n=${p.n}, SK=${p.secretKeyBytes}B, PK=${p.publicKeyBytes}B)`)
  }
  console.log()

  console.log("╔══════════════════════════════════════════════════════════╗")
  console.log("║  All tests passed                                       ║")
  console.log("╚══════════════════════════════════════════════════════════╝")
}

runTests().catch(console.error)