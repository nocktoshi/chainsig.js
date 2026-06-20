//
// Given the MPC FrostCheetah ROOT public key from the live cluster's contract, a
// (predecessor, path), and a cluster-produced signature (c, s) over a known
// 5-belt digest, this:
//   1. derives the child public key the SAME way the chainsig Nockchain adapter
//      does (`deriveMpcAddress` — root + epsilon tweak), and
//   2. verifies the cluster's signature against that derived child key.
//
// Success proves the adapter's derivation matches the contract's kdf AND the
// cluster signed a valid Cheetah signature for the adapter-derived key.
//
// argv: <rootPubHex> <predecessor> <path> <cHex> <sHex> <beltsCsv>
import {
  deriveMpcAddress,
  publicKeyVerify,
  digestToBase58,
} from '@nockchain/rose-ts'

const [, , rootPubHex, predecessor, path, cHex, sHex, beltsCsv] = process.argv

const fromHex = (s) =>
  Uint8Array.from((s.match(/.{1,2}/g) ?? []).map((h) => parseInt(h, 16)))

// Derive the child public key exactly as the adapter's deriveAddressAndPublicKey.
const { publicKey: childPub, pkh } = deriveMpcAddress(
  fromHex(rootPubHex),
  predecessor,
  path
)

// The 5-belt digest the cluster signed, as the base58 Digest `verify` expects.
const belts = beltsCsv.split(',').map((b) => BigInt(b))
const digest = digestToBase58(belts)

const ok = publicKeyVerify(childPub, digest, { c: cHex, s: sHex })

console.log(`derived child PKH: ${String(pkh)}`)
console.log(`derived child pubkey (be hex): ${[...childPub.toBeBytes()].map((x) => x.toString(16).padStart(2, '0')).join('')}`)
console.log(ok ? 'VERIFY_OK' : 'VERIFY_FAIL')
process.exit(ok ? 0 : 1)
