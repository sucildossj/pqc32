/**
 * FIPS 205 Parameter Sets
 *
 * Values from NIST FIPS 205 Table 1.
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf
 */

import { SLHDSAParamSet } from "./types"

export const SLH_DSA_SHAKE_128S: SLHDSAParamSet = {
  name: "SLH-DSA-SHAKE-128s",
  n: 16,
  securityLevel: 1,
  secretKeyBytes: 64,
  publicKeyBytes: 32,
  signatureBytes: 7856,
  h: 63,
  d: 7,
  hp: 9,
  a: 12,
  k: 14,
  keygenRandomnessBytes: 48,
  algorithmId: 0x01,
}

export const SLH_DSA_SHAKE_128F: SLHDSAParamSet = {
  name: "SLH-DSA-SHAKE-128f",
  n: 16,
  securityLevel: 1,
  secretKeyBytes: 64,
  publicKeyBytes: 32,
  signatureBytes: 17088,
  h: 66,
  d: 22,
  hp: 3,
  a: 6,
  k: 33,
  keygenRandomnessBytes: 48,
  algorithmId: 0x02,
}

export const SLH_DSA_SHAKE_256S: SLHDSAParamSet = {
  name: "SLH-DSA-SHAKE-256s",
  n: 32,
  securityLevel: 5,
  secretKeyBytes: 128,
  publicKeyBytes: 64,
  signatureBytes: 29792,
  h: 64,
  d: 8,
  hp: 8,
  a: 14,
  k: 22,
  keygenRandomnessBytes: 96,
  algorithmId: 0x03,
}

/**
 * Algorithm registry — maps ID byte to parameter set.
 * Used by xprv deserialization to auto-detect algorithm.
 */
export const ALGORITHM_REGISTRY: Record<number, SLHDSAParamSet> = {
  0x01: SLH_DSA_SHAKE_128S,
  0x02: SLH_DSA_SHAKE_128F,
  0x03: SLH_DSA_SHAKE_256S,
}

/** Default algorithm */
export const DEFAULT_ALGORITHM = SLH_DSA_SHAKE_128S