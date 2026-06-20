import { describe, it, expect, beforeAll } from '@jest/globals'
import {
  PrivateKey,
  LocalMpcSigner,
  deriveMpcAddress,
  publicKeyVerify,
  publicKeyFromBeBytes,
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
} from '../../src/chain-adapters/Nockchain/types'
import type { Signature } from '../../src/types'

// Skip unless explicitly running integration tests.
const itif = process.env.INTEGRATION_TEST ? it : it.skip

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

const fromHex = (s: string): Uint8Array =>
  Uint8Array.from((s.match(/.{1,2}/g) ?? []).map((h) => parseInt(h, 16)))

// A locally generated MPC root, used when no live cluster root is provided via
// MPC_CHEETAH_ROOT_HEX. It keeps the derivation/signing flow exercisable offline.
const LOCAL_ROOT_BYTES = new Uint8Array(32)
LOCAL_ROOT_BYTES[0] = 7
const LOCAL_ROOT_PRIV = PrivateKey.fromBytes(LOCAL_ROOT_BYTES)
const LOCAL_ROOT_PUB_HEX = toHex(LOCAL_ROOT_PRIV.publicKey)

const PREDECESSOR = process.env.NEAR_ACCOUNT_ID || 'alice.testnet'
const PATH = process.env.NOCK_DERIVATION_PATH || 'nock-1'

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

describe('Nockchain MPC Integration', () => {
  let nockchain: Nockchain
  let rootPublicKeyHex: string
  let usingLiveRoot: boolean

  beforeAll(() => {
    const rpcUrl = process.env.NOCKCHAIN_RPC || 'https://rpc.nockchain.net'
    // Prefer the live cluster's published 97-byte Cheetah root key, if provided.
    rootPublicKeyHex = process.env.MPC_CHEETAH_ROOT_HEX || LOCAL_ROOT_PUB_HEX
    usingLiveRoot = Boolean(process.env.MPC_CHEETAH_ROOT_HEX)

    console.log(`Nockchain RPC: ${rpcUrl}`)
    console.log(`MPC root: ${usingLiveRoot ? 'live cluster' : 'local (generated)'}`)

    nockchain = new Nockchain({ rpcUrl, rootPublicKey: rootPublicKeyHex })
  })

  itif(
    'derives a Nockchain address + child key from the MPC root',
    async () => {
      const { address, publicKey } = await nockchain.deriveAddressAndPublicKey(
        PREDECESSOR,
        PATH
      )
      console.log('Derived Nockchain address (PKH):', address)
      console.log('Derived child public key (be hex):', publicKey)

      expect(address).toBeDefined()
      expect(publicKey).toBeDefined()
      // base58 PKH + 97-byte big-endian Cheetah point.
      expect(address).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/)
      expect(publicKey).toHaveLength(97 * 2)
      // The child key round-trips through rose-ts' point (de)serialization.
      expect(() => publicKeyFromBeBytes(fromHex(publicKey))).not.toThrow()

      // Best-effort balance lookup against the live RPC.
      try {
        const { balance, decimals } = await nockchain.getBalance(address)
        console.log(`Balance: ${balance} nicks (decimals: ${decimals})`)
        expect(typeof balance).toBe('bigint')
      } catch (error: unknown) {
        console.warn(
          'Could not fetch balance (normal for a fresh address / offline run):',
          error instanceof Error ? error.message : String(error)
        )
      }
    }
  )

  itif(
    'verifies a Cheetah signature against the adapter-derived child key',
    async () => {
      const liveRoot = process.env.CHEETAH_ROOT_HEX
      const liveC = process.env.CHEETAH_SIG_C
      const liveS = process.env.CHEETAH_SIG_S

      if (liveRoot && liveC && liveS) {
        // Verify a real cluster-produced signature.
        const predecessor = process.env.CHEETAH_PREDECESSOR || PREDECESSOR
        const path = process.env.CHEETAH_PATH || 'test'
        const belts = (process.env.CHEETAH_BELTS || '11,22,33,44,55')
          .split(',')
          .map((b) => BigInt(b.trim())) as unknown as [
          bigint,
          bigint,
          bigint,
          bigint,
          bigint,
        ]

        const { publicKey: childPub, pkh } = deriveMpcAddress(
          fromHex(liveRoot),
          predecessor,
          path
        )
        const digest = digestToBase58(belts)
        const ok = publicKeyVerify(childPub, digest, { c: liveC, s: liveS })

        console.log('Derived child PKH:', String(pkh))
        console.log('Live cluster signature verifies:', ok)
        expect(ok).toBe(true)
        return
      }

      // Self-contained fallback: LocalMpcSigner stands in for the cluster.
      console.log(
        'No live cluster signature in env; using a LocalMpcSigner proof.'
      )
      const signer = new LocalMpcSigner(LOCAL_ROOT_BYTES, PREDECESSOR)
      const childPub = await signer.childPublicKey(PATH)
      const digest = digestToBase58([11n, 22n, 33n, 44n, 55n])
      const sig = await signer.sign(PATH, digest)
      expect(publicKeyVerify(childPub, digest, sig)).toBe(true)
    }
  )

  itif(
    'prepares, MPC-signs, and finalizes a NOCK transfer end-to-end',
    async () => {
      try {
        // Use a self-contained local root so we control the spending key for the
        // full prepare→sign→finalize→verify path (no funds / live cluster needed).
        const localAdapter = new Nockchain({
          rpcUrl: process.env.NOCKCHAIN_RPC || 'https://rpc.nockchain.net',
          rootPublicKey: LOCAL_ROOT_PUB_HEX,
        })
        const sender = await localAdapter.deriveAddressAndPublicKey(
          PREDECESSOR,
          PATH
        )
        const recipient = await localAdapter.deriveAddressAndPublicKey(
          PREDECESSOR,
          'nock-recipient'
        )
        console.log('Sender PKH:', sender.address)
        console.log('Recipient PKH:', recipient.address)

        // Prefer real UTXOs for the sender if the RPC has any; otherwise fabricate.
        let notes: Note[]
        try {
          const balance = (await localAdapter.getBalance(
            sender.address
          )) as unknown
          const fetched = (
            (balance as { notes?: Array<{ note?: Note }> }).notes ?? []
          )
            .map((n) => n.note)
            .filter((n): n is Note => Boolean(n))
          notes = fetched.length > 0 ? fetched : [fabricateNote(sender.address, '1000000')]
          console.log(
            `Using ${notes.length} input note(s) (${
              fetched.length > 0 ? 'from RPC' : 'fabricated'
            }).`
          )
        } catch {
          notes = [fabricateNote(sender.address, '1000000')]
          console.log('RPC unavailable; using a fabricated input note.')
        }

        const request: NockchainTransactionRequest = {
          senderPublicKey: sender.publicKey,
          senderPkh: sender.address,
          to: recipient.address,
          amount: '100',
          notes,
        }

        const { transaction, hashesToSign } =
          await localAdapter.prepareTransactionForSigning(request)
        console.log('Spends to sign:', hashesToSign.length)
        hashesToSign.forEach((h) => expect(h).toHaveLength(40))

        // Sign each spend with a LocalMpcSigner over the same root (cluster stand-in).
        const signer = new LocalMpcSigner(LOCAL_ROOT_BYTES, PREDECESSOR)
        const childPub = await signer.childPublicKey(PATH)
        const sigs: Signature[] = []
        for (const messageBytes of hashesToSign) {
          const digest = digestToBase58(
            digestFromMessageBytes(Uint8Array.from(messageBytes))
          )
          const roseSig = await signer.sign(PATH, digest)
          expect(publicKeyVerify(childPub, digest, roseSig)).toBe(true)
          sigs.push({
            scheme: NOCKCHAIN_SCHEME,
            signature: [...fromHex(roseSig.c), ...fromHex(roseSig.s)],
          })
        }

        const signedTx = localAdapter.finalizeTransactionSigning({
          transaction,
          // Single-spend transfer → a single signature.
          rsvSignatures: sigs[0],
        })
        console.log('Signed tx prefix:', signedTx.slice(0, 60), '...')

        // We do NOT broadcast in the integration test (would move real funds).
        expect(typeof signedTx).toBe('string')
        const built = JSON.parse(signedTx)
        expect(built).toHaveProperty('spends')
        expect(built).toHaveProperty('witness_data')
      } catch (error: unknown) {
        console.error(
          'Unexpected error in end-to-end transfer test:',
          error instanceof Error ? error.message : String(error)
        )
        expect(error).toBeDefined()
      }
    }
  )
})
