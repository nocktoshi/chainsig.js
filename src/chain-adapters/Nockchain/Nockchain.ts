import {
  RpcClient,
  TxBuilder,
  deriveMpcAddress,
  digestToMessageBytes,
  hashPublicKey,
  hashSpendV1SigHash,
  lockFromList,
  pkhSingle,
  publicKeyFromBeBytes,
  spendConditionNewPkh,
  txEngineSettingsV1BythosDefault,
  type NockchainTx,
  type Signature as RoseSignature,
} from '@nockchain/rose-ts'

import { type Transaction } from '@solana/web3.js'

import { ChainAdapter } from '../ChainAdapter'

import type { HashToSign, RSVSignature, Signature } from '@types'

import type {
  NockchainTransactionRequest,
  NockchainUnsignedTransaction,
} from './types'

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

const fromHex = (s: string): Uint8Array =>
  Uint8Array.from((s.match(/.{1,2}/g) ?? []).map((h) => parseInt(h, 16)))

export interface NockchainConfig {
  /** Nockchain RPC endpoint. */
  rpcUrl: string
  /**
   * The MPC root public key for the Nockchain (Cheetah) domain — the 97-byte
   * big-endian point published by the NEAR MPC contract, as hex or bytes.
   * Address/key derivation tweaks this root per (predecessor, path).
   */
  rootPublicKey: string | Uint8Array
  /** Optional custom fetch implementation forwarded to the rose-ts RPC client. */
  fetchFn?: ConstructorParameters<typeof RpcClient>[1]
}

/**
 * chainsig.js chain adapter for **Nockchain**, signing remotely via the NEAR MPC
 * cluster's `FrostCheetah` domain (key-prefixed Schnorr over the Cheetah curve
 * with a Tip5 challenge).
 *
 * The heavy lifting (key-derivation tweak, transaction building, per-spend
 * sighash, witness assembly) is delegated to `@nockchain/rose-ts`; this adapter
 * adapts it to chainsig's prepare/sign/finalize MPC flow.
 */
export class Nockchain extends ChainAdapter<
  NockchainTransactionRequest,
  NockchainUnsignedTransaction
> {
  private readonly rpc: RpcClient
  private readonly rootPublicKey: Uint8Array

  constructor(config: NockchainConfig) {
    super()
    this.rpc = new RpcClient(config.rpcUrl, config.fetchFn)
    this.rootPublicKey =
      typeof config.rootPublicKey === 'string'
        ? fromHex(config.rootPublicKey)
        : config.rootPublicKey
  }

  /**
   * Derive a Nockchain address (PKH, base58) + child public key for a NEAR
   * account and path, using NEAR's epsilon-derivation tweak applied to the
   * Cheetah root key (`childPub = root + tweak·G`).
   */
  async deriveAddressAndPublicKey(
    predecessor: string,
    path: string
  ): Promise<{ address: string; publicKey: string }> {
    const { publicKey, pkh } = deriveMpcAddress(
      this.rootPublicKey,
      predecessor,
      path
    )
    return { address: String(pkh), publicKey: toHex(publicKey.toBeBytes()) }
  }

  /** Total spendable balance (in nicks, the NOCK base unit) at an address. */
  async getBalance(
    address: string
  ): Promise<{ balance: bigint; decimals: number }> {
    const balance = await this.rpc.getBalance(address)
    const total = (balance.notes ?? []).reduce<bigint>((sum, entry) => {
      const assets = (entry as { note?: { assets?: unknown } }).note?.assets
      return assets == null ? sum : sum + BigInt(String(assets))
    }, 0n)
    // NOCK's base unit is the nick (2^16 nicks = 1 NOCK); balance is raw nicks.
    return { balance: total, decimals: 0 }
  }

  serializeTransaction(transaction: NockchainUnsignedTransaction): string {
    return JSON.stringify(transaction)
  }

  deserializeTransaction(serialized: string): NockchainUnsignedTransaction {
    return JSON.parse(serialized) as NockchainUnsignedTransaction
  }

  /**
   * Build the spend and emit the per-spend signing digests as `hashesToSign`.
   *
   * The digest is the spend sighash encoded as the 40-byte (5-belt) Tip5 message
   * that the `FrostCheetah` domain signs — i.e. what gets submitted to the MPC
   * contract as the `Eddsa` byte payload. Their order matches the spends, which
   * is the order signatures must come back in for {@link finalizeTransactionSigning}.
   */
  async prepareTransactionForSigning(
    transactionRequest: NockchainTransactionRequest
  ): Promise<{
    transaction: NockchainUnsignedTransaction
    hashesToSign: HashToSign[]
  }> {
    const transaction: NockchainUnsignedTransaction = {
      senderPkh: transactionRequest.senderPkh,
      recipientPkh: transactionRequest.to,
      refundPkh: transactionRequest.refundPkh ?? transactionRequest.senderPkh,
      amount: transactionRequest.amount,
      notes: transactionRequest.notes,
      childPublicKeyHex: transactionRequest.senderPublicKey,
    }

    const builder = this.buildBuilder(transaction)
    const hashesToSign: HashToSign[] = builder.allSpends().map((sb) => {
      const spend = sb.spend
      if (spend.tag !== 1) {
        throw new Error('Nockchain: expected a PKH (tag-1) spend')
      }
      return Array.from(digestToMessageBytes(hashSpendV1SigHash(spend)))
    })

    return { transaction, hashesToSign }
  }

  /**
   * Attach the MPC-produced Cheetah signatures to the spends and return the
   * serialized signed transaction. `rsvSignatures[i]` must correspond to
   * `hashesToSign[i]` from {@link prepareTransactionForSigning}.
   */
  finalizeTransactionSigning({
    transaction,
    rsvSignatures,
  }: {
    transaction: Transaction | NockchainUnsignedTransaction
    rsvSignatures: RSVSignature[] | Signature
  }): string {
    const tx = transaction as NockchainUnsignedTransaction
    const childPub = fromHex(tx.childPublicKeyHex)
    const pkh = hashPublicKey(childPub)
    const pubkeyBase58 = publicKeyFromBeBytes(childPub).toBase58()
    // Cheetah is multi-spend: expect one { scheme, signature } per spend.
    const sigList = (
      Array.isArray(rsvSignatures) ? rsvSignatures : [rsvSignatures]
    ) as unknown as Signature[]
    const sigs = sigList.map(toRoseSignature)

    const builder = this.buildBuilder(tx)
    const spends = builder.allSpends()
    if (spends.length !== sigs.length) {
      throw new Error(
        `Nockchain finalize: expected ${spends.length} signatures, got ${sigs.length}`
      )
    }
    spends.forEach((sb, i) => {
      sb.pushPkhSignature(pkh, pubkeyBase58, sigs[i])
    })

    return JSON.stringify(builder.build())
  }

  async broadcastTx(txSerialized: string): Promise<{ hash: string }> {
    const tx = JSON.parse(txSerialized) as NockchainTx
    const hash = await this.rpc.sendTransaction(tx)
    return { hash }
  }

  /**
   * Deterministically (re)build the spend from the recipe. Called by both
   * prepare (to compute digests) and finalize (to attach signatures), so it must
   * be a pure function of the recipe.
   */
  private buildBuilder(tx: NockchainUnsignedTransaction): TxBuilder {
    const builder = new TxBuilder(txEngineSettingsV1BythosDefault())
    // Every input note is P2PKH-locked to the sender's (derived) address.
    const inputLock = lockFromList([
      spendConditionNewPkh(pkhSingle(tx.senderPkh as never)),
    ])
    const txLocks = tx.notes.map(() => ({ lock: inputLock, lock_sp_index: 0 }))
    builder.simpleSpend(
      tx.notes,
      txLocks as never,
      tx.recipientPkh as never,
      tx.amount as never,
      undefined, // fee_override — recalcAndSetFee computes it
      tx.refundPkh as never,
      false
    )
    builder.recalcAndSetFee(false)
    return builder
  }
}

/** Convert a chainsig 64-byte Cheetah signature (`c‖s`) to rose-ts `{ c, s }`. */
function toRoseSignature(sig: Signature): RoseSignature {
  const bytes = Uint8Array.from(sig.signature)
  if (bytes.length !== 64) {
    throw new Error(
      `Nockchain: Cheetah signature must be 64 bytes (c‖s), got ${bytes.length}`
    )
  }
  return {
    c: toHex(bytes.subarray(0, 32)),
    s: toHex(bytes.subarray(32, 64)),
  }
}
