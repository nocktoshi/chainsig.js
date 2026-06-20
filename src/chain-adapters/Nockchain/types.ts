import type { Note } from '@nockchain/rose-ts'

/**
 * Scheme tag for the key-prefixed Schnorr (Cheetah/Tip5) signatures produced by
 * the Nockchain MPC domain (`Protocol::FrostCheetah` / `Curve::Cheetah`).
 */
export const NOCKCHAIN_SCHEME = 'SchnorrCheetah' as const

/**
 * A request to build a simple PKH→PKH NOCK transfer to be signed remotely by the
 * MPC cluster.
 *
 * UTXO selection is left to the caller: `notes` are the input notes (all
 * P2PKH-locked to `senderPkh`) to spend. The bulk goes to `to`; the remainder
 * (minus fee) refunds to `refundPkh` (defaults to the sender).
 */
export interface NockchainTransactionRequest {
  /** Sender's child public key (97-byte big-endian, hex) from {@link Nockchain.deriveAddressAndPublicKey}. */
  senderPublicKey: string
  /** Sender's child address / PKH (base58) — owner of the input notes. */
  senderPkh: string
  /** Recipient address / PKH (base58). */
  to: string
  /** Amount to transfer, in nicks (NOCK base unit), as a decimal string. */
  amount: string
  /** Input notes (UTXOs) owned by `senderPkh`. */
  notes: Note[]
  /** Where change/refund goes (base58 PKH). Defaults to `senderPkh`. */
  refundPkh?: string
}

/**
 * An opaque unsigned transaction: a deterministic build recipe plus the signing
 * public key. {@link Nockchain.prepareTransactionForSigning} (which captures the
 * per-spend digests) and {@link Nockchain.finalizeTransactionSigning} (which
 * attaches the MPC signatures) reconstruct the identical transaction from it.
 */
export interface NockchainUnsignedTransaction {
  senderPkh: string
  recipientPkh: string
  refundPkh: string
  amount: string
  notes: Note[]
  /** Sender's child public key, 97-byte big-endian, hex (drives the witness + PKH). */
  childPublicKeyHex: string
}
