import { describe, it, expect, beforeEach, jest } from '@jest/globals'
import {
  PrivateKey,
  LocalMpcSigner,
  deriveMpcAddress,
  publicKeyVerify,
  lockFromList,
  spendConditionNewPkh,
  pkhSingle,
  lockRootHash,
  nameV1,
  noteDataEmpty,
  digestToBase58,
  digestFromMessageBytes,
  type Note,
} from '@nockchain/rose-ts'

import { Nockchain } from '../../src/chain-adapters/Nockchain/Nockchain'
import {
  NOCKCHAIN_SCHEME,
  type NockchainTransactionRequest,
  type NockchainUnsignedTransaction,
} from '../../src/chain-adapters/Nockchain/types'
import type { Signature } from '../../src/types'

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

const fromHex = (s: string): Uint8Array =>
  Uint8Array.from((s.match(/.{1,2}/g) ?? []).map((h) => parseInt(h, 16)))

// A deterministic MPC root key. In production this is the 97-byte Cheetah point
// the NEAR MPC contract publishes; here we generate one locally so the adapter's
// derivation/signing can be exercised end-to-end without a live cluster.
const ROOT_BYTES = new Uint8Array(32)
ROOT_BYTES[0] = 7
const ROOT_PRIV = PrivateKey.fromBytes(ROOT_BYTES)
const ROOT_PUB_HEX = toHex(ROOT_PRIV.publicKey)

const PREDECESSOR = 'alice.testnet'
const PATH = 'nock-1'

/**
 * Fabricate a coinbase-style note (UTXO) P2PKH-locked to `ownerPkh` holding
 * `assets` nicks — enough scaffolding for `TxBuilder.simpleSpend` to select it.
 */
function fabricateNote(ownerPkh: string, assets: string): Note {
  const lock = lockFromList([spendConditionNewPkh(pkhSingle(ownerPkh as never))])
  const source = {
    hash: digestToBase58([9n, 9n, 9n, 9n, 9n]),
    is_coinbase: true,
  }
  const name = nameV1(lockRootHash(lock), source as never)
  return {
    version: 1,
    origin_page: 0,
    name,
    note_data: noteDataEmpty(),
    assets: assets as never,
    lock,
    source,
  } as unknown as Note
}

/** Pack a rose-ts `{ c, s }` (LE hex) into a chainsig `Signature` (64-byte c‖s). */
function asChainsigSignature(c: string, s: string): Signature {
  return {
    scheme: NOCKCHAIN_SCHEME,
    signature: [...fromHex(c), ...fromHex(s)],
  }
}

type BalanceResponse = { notes: Array<{ note?: { assets?: unknown } }> }
type RpcMock = {
  getBalance: jest.Mock<(address: string) => Promise<BalanceResponse>>
  sendTransaction: jest.Mock<(tx: unknown) => Promise<string>>
}

describe('Nockchain Chain Adapter', () => {
  let nockchain: Nockchain
  let rpc: RpcMock

  beforeEach(() => {
    nockchain = new Nockchain({
      rpcUrl: 'http://localhost:3030',
      rootPublicKey: ROOT_PUB_HEX,
    })
    // Replace the internal rose-ts RPC client with mocks — these unit tests
    // never touch the network.
    rpc = {
      getBalance: jest.fn<(address: string) => Promise<BalanceResponse>>(),
      sendTransaction: jest.fn<(tx: unknown) => Promise<string>>(),
    }
    ;(nockchain as unknown as { rpc: RpcMock }).rpc = rpc
  })

  it('should derive address and public key', async () => {
    const { address, publicKey } = await nockchain.deriveAddressAndPublicKey(
      PREDECESSOR,
      PATH
    )

    // Cross-check against rose-ts' derivation directly.
    const direct = deriveMpcAddress(ROOT_PRIV.publicKey, PREDECESSOR, PATH)
    expect(address).toBe(String(direct.pkh))
    expect(publicKey).toBe(toHex(direct.publicKey.toBeBytes()))

    // The derived child key is a 97-byte big-endian Cheetah point.
    expect(publicKey).toHaveLength(97 * 2)
    // The address is a base58 PKH (no 0/O/I/l).
    expect(address).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/)
  })

  it('should derive distinct child keys for distinct paths', async () => {
    const a = await nockchain.deriveAddressAndPublicKey(PREDECESSOR, 'nock-1')
    const b = await nockchain.deriveAddressAndPublicKey(PREDECESSOR, 'nock-2')
    expect(a.address).not.toBe(b.address)
    expect(a.publicKey).not.toBe(b.publicKey)
  })

  it('should get balance by summing note assets', async () => {
    rpc.getBalance.mockResolvedValue({
      notes: [{ note: { assets: '1000' } }, { note: { assets: '337' } }],
    })

    const { balance, decimals } = await nockchain.getBalance('some-pkh')
    expect(balance).toBe(1337n)
    // NOCK balances are reported in raw nicks (integer base unit).
    expect(decimals).toBe(0)
  })

  it('should report a zero balance for an empty/unknown address', async () => {
    rpc.getBalance.mockResolvedValue({ notes: [] })

    const { balance } = await nockchain.getBalance('empty-pkh')
    expect(balance).toBe(0n)
  })

  it('should serialize and deserialize a transaction', async () => {
    const { address, publicKey } = await nockchain.deriveAddressAndPublicKey(
      PREDECESSOR,
      PATH
    )
    const unsigned: NockchainUnsignedTransaction = {
      senderPkh: address,
      recipientPkh: address,
      refundPkh: address,
      amount: '100',
      notes: [fabricateNote(address, '1000000')],
      childPublicKeyHex: publicKey,
    }

    const roundTripped = nockchain.deserializeTransaction(
      nockchain.serializeTransaction(unsigned)
    )
    expect(roundTripped).toEqual(unsigned)
  })

  it('should prepare a transfer and emit per-spend Tip5 signing digests', async () => {
    const sender = await nockchain.deriveAddressAndPublicKey(PREDECESSOR, PATH)
    const recipient = await nockchain.deriveAddressAndPublicKey(
      PREDECESSOR,
      'nock-2'
    )
    const request: NockchainTransactionRequest = {
      senderPublicKey: sender.publicKey,
      senderPkh: sender.address,
      to: recipient.address,
      amount: '100',
      notes: [fabricateNote(sender.address, '1000000')],
    }

    const { transaction, hashesToSign } =
      await nockchain.prepareTransactionForSigning(request)

    expect(transaction.senderPkh).toBe(sender.address)
    expect(transaction.recipientPkh).toBe(recipient.address)
    // Sender refunds itself by default.
    expect(transaction.refundPkh).toBe(sender.address)
    expect(transaction.childPublicKeyHex).toBe(sender.publicKey)

    expect(hashesToSign.length).toBeGreaterThan(0)
    // Each digest is the 5-belt Tip5 message = 40 little-endian bytes.
    hashesToSign.forEach((h) => expect(h).toHaveLength(40))
  })

  it('should prepare, MPC-sign, finalize, and verify a full transfer', async () => {
    const sender = await nockchain.deriveAddressAndPublicKey(PREDECESSOR, PATH)
    const recipient = await nockchain.deriveAddressAndPublicKey(
      PREDECESSOR,
      'nock-2'
    )
    const request: NockchainTransactionRequest = {
      senderPublicKey: sender.publicKey,
      senderPkh: sender.address,
      to: recipient.address,
      amount: '100',
      notes: [fabricateNote(sender.address, '1000000')],
    }

    const { transaction, hashesToSign } =
      await nockchain.prepareTransactionForSigning(request)
    // A single input note produces a single spend.
    expect(hashesToSign).toHaveLength(1)

    // Stand in for the MPC cluster: a LocalMpcSigner over the same root key signs
    // the emitted digest exactly as the FrostCheetah domain would.
    const signer = new LocalMpcSigner(ROOT_BYTES, PREDECESSOR)
    const childPub = await signer.childPublicKey(PATH)
    // The adapter exposes the derived key; it must match the signer's child key.
    expect(toHex(childPub.toBeBytes())).toBe(sender.publicKey)

    // hashesToSign carries the 40-byte Tip5 message; recover the base58 Digest.
    const digest = digestToBase58(
      digestFromMessageBytes(Uint8Array.from(hashesToSign[0]))
    )
    const roseSig = await signer.sign(PATH, digest)

    // The cluster's signature verifies under the adapter-derived child key.
    expect(publicKeyVerify(childPub, digest, roseSig)).toBe(true)

    // Hand the signature back to the adapter to assemble the signed transaction.
    const signedTx = nockchain.finalizeTransactionSigning({
      transaction,
      rsvSignatures: asChainsigSignature(roseSig.c, roseSig.s),
    })

    expect(typeof signedTx).toBe('string')
    const built = JSON.parse(signedTx)
    expect(built).toHaveProperty('spends')
    expect(built).toHaveProperty('witness_data')
  })

  it('should reject a malformed (non-64-byte) Cheetah signature in finalize', async () => {
    const { address, publicKey } = await nockchain.deriveAddressAndPublicKey(
      PREDECESSOR,
      PATH
    )
    const transaction: NockchainUnsignedTransaction = {
      senderPkh: address,
      recipientPkh: address,
      refundPkh: address,
      amount: '100',
      notes: [fabricateNote(address, '1000000')],
      childPublicKeyHex: publicKey,
    }

    expect(() =>
      nockchain.finalizeTransactionSigning({
        transaction,
        // 32 bytes — not a valid c‖s pair.
        rsvSignatures: { scheme: NOCKCHAIN_SCHEME, signature: new Array(32).fill(0) },
      })
    ).toThrow(/64 bytes/)
  })

  it('should broadcast a transaction via the RPC client', async () => {
    rpc.sendTransaction.mockResolvedValue('0xdeadbeefhash')

    const { hash } = await nockchain.broadcastTx(
      JSON.stringify({ version: 1, spends: [], witness_data: [] })
    )
    expect(hash).toBe('0xdeadbeefhash')
  })
})
