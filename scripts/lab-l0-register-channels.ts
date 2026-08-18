#!/usr/bin/env npx tsx
/**
 * Lab-only: create extra per-port routing EOAs (beacon :4200, udp :4300),
 * register them on the host's existing mailbox B, write key files.
 * Reuses existing geth routing identity. Does not log private keys or full armor.
 *
 *   npx tsx src/conet-l0d/scripts/lab-l0-register-channels.ts
 */
import { createRequire } from 'node:module'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { webcrypto } from 'node:crypto'
import { ethers } from 'ethers'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const CRATE = path.join(__dirname, '..')
const ROOT = path.join(CRATE, '..', '..')

const RPC = process.env.CONET_RPC || 'https://rpc1.conet.network'
const ADDRESS_PGP = '0x684b0ac760cEE9c9b85de36d69746420648Cf9e2'
const REGISTER_URL = process.env.REGIEST_URL || 'https://beamio.app/api/regiestChatRoute'
const OUT_DIR = process.env.LAB_L0_OUT || path.join(CRATE, 'lab-secrets')

const CHANNELS = [
	{ name: 'geth', ports: [8400], service: 'geth' },
	{ name: 'beacon', ports: [4200], service: 'beacon' },
	{ name: 'udp', ports: [4300], service: 'beacon' },
] as const

type OpenPgpMod = typeof import('openpgp')

type SearchKeyRow = {
	userPgpKeyID: string
	userPublicKeyArmoredB64: string
	routeKeyID: string
	routePublicKeyArmoredB64: string
}

type Identity = {
	label: string
	address: string
	privateKey: string
	publicArmor: string
	privateArmor: string
	keyID: string
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms))
}

async function loadOpenPgp(): Promise<OpenPgpMod> {
	const candidates = [
		path.join(ROOT, 'src/SilentPassUI/node_modules/openpgp/dist/node/openpgp.mjs'),
		path.join(ROOT, 'src/bizSite/node_modules/openpgp/dist/node/openpgp.mjs'),
	]
	for (const p of candidates) {
		if (!fs.existsSync(p)) continue
		return (await import(pathToFileURL(p).href)) as OpenPgpMod
	}
	const req = createRequire(path.join(ROOT, 'src/bizSite/package.json'))
	return req('openpgp') as OpenPgpMod
}

async function aesGcmEncrypt(plaintext: string, password: string): Promise<string> {
	const pwUtf8 = new TextEncoder().encode(password)
	const pwHash = await webcrypto.subtle.digest('SHA-256', pwUtf8)
	const iv = webcrypto.getRandomValues(new Uint8Array(12))
	const key = await webcrypto.subtle.importKey(
		'raw',
		pwHash,
		{ name: 'AES-GCM', iv },
		false,
		['encrypt'],
	)
	const ct = new Uint8Array(
		await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)),
	)
	const combined = new Uint8Array(iv.length + ct.length)
	combined.set(iv, 0)
	combined.set(ct, iv.length)
	return Buffer.from(combined).toString('base64')
}

async function searchKey(provider: ethers.Provider, wallet: string): Promise<SearchKeyRow> {
	const pgp = new ethers.Contract(
		ADDRESS_PGP,
		['function searchKey(address) view returns (string,string,string,string,bool)'],
		provider,
	)
	const sk = (await pgp.searchKey(ethers.getAddress(wallet))) as [
		string,
		string,
		string,
		string,
		boolean,
	]
	return {
		userPgpKeyID: String(sk[0] ?? ''),
		userPublicKeyArmoredB64: String(sk[1] ?? ''),
		routeKeyID: String(sk[2] ?? '').toUpperCase(),
		routePublicKeyArmoredB64: String(sk[3] ?? ''),
	}
}

async function generateIdentity(openpgp: OpenPgpMod, label: string): Promise<Identity> {
	const wallet = ethers.Wallet.createRandom()
	const { privateKey, publicKey } = await openpgp.generateKey({
		type: 'ecc',
		curve: 'curve25519',
		userIDs: [{ name: wallet.address }],
		format: 'armored',
		passphrase: '',
	})
	const keyObj = await openpgp.readKey({ armoredKey: publicKey })
	const keyID = keyObj.getKeyIDs()[1].toHex().toUpperCase()
	console.log(`[ok] ${label} routing_eoa=${wallet.address} keyID=${keyID.slice(0, 12)}…`)
	return {
		label,
		address: wallet.address,
		privateKey: wallet.privateKey,
		publicArmor: publicKey,
		privateArmor: privateKey,
		keyID,
	}
}

async function registerRoute(id: Identity, routeKeyID: string) {
	const encrypKeyArmored = await aesGcmEncrypt(id.privateArmor, id.privateKey)
	const body = {
		wallet: id.address,
		keyID: id.keyID,
		publicKeyArmored: Buffer.from(id.publicArmor, 'utf8').toString('base64'),
		encrypKeyArmored,
		routeKeyID,
	}
	let lastErr = ''
	for (let attempt = 1; attempt <= 8; attempt++) {
		const res = await fetch(REGISTER_URL, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(body),
		})
		const json = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string }
		const err = `${json.error ?? ''}`.trim()
		if (res.ok && json.ok !== false) {
			console.log(`[ok] ${id.label} queued on mailbox B=${routeKeyID}`)
			return
		}
		lastErr = `${id.label} regiestChatRoute ${res.status} ${err}`.trim()
		const retryable = /replacement fee too low|already known|nonce too low|busy|timeout/i.test(err)
		if (!retryable || attempt === 8) throw new Error(lastErr)
		const waitMs = 8000 * attempt
		console.warn(`[warn] ${lastErr}; retry ${attempt}/8 in ${waitMs}ms`)
		await sleep(waitMs)
	}
	throw new Error(lastErr)
}

function writeSecret(file: string, contents: string, mode = 0o600) {
	fs.mkdirSync(path.dirname(file), { recursive: true })
	fs.writeFileSync(file, contents.endsWith('\n') ? contents : `${contents}\n`, { mode })
	fs.chmodSync(file, mode)
}

function decodeArmorB64(raw: string): string {
	const t = raw.trim()
	if (t.includes('BEGIN PGP')) return t
	return Buffer.from(t, 'base64').toString('utf8')
}

async function loadOrCreateIdentity(
	openpgp: OpenPgpMod,
	label: string,
	dir: string,
): Promise<Identity> {
	const ethFile = path.join(dir, 'routing.eth')
	const keyFile = path.join(dir, 'routing.key')
	const pubFile = path.join(dir, 'self-user.asc')
	if (fs.existsSync(ethFile) && fs.existsSync(keyFile) && fs.existsSync(pubFile)) {
		const privateKey = fs.readFileSync(ethFile, 'utf8').trim()
		const privateArmor = fs.readFileSync(keyFile, 'utf8')
		const publicArmor = fs.readFileSync(pubFile, 'utf8')
		const wallet = new ethers.Wallet(privateKey)
		const keyObj = await openpgp.readKey({ armoredKey: publicArmor })
		const keyID = keyObj.getKeyIDs()[1].toHex().toUpperCase()
		console.log(`[ok] ${label} reuse routing_eoa=${wallet.address} keyID=${keyID.slice(0, 12)}…`)
		return { label, address: wallet.address, privateKey, publicArmor, privateArmor, keyID }
	}
	const id = await generateIdentity(openpgp, label)
	writeSecret(ethFile, id.privateKey)
	writeSecret(keyFile, id.privateArmor)
	writeSecret(pubFile, id.publicArmor, 0o644)
	return id
}

async function pollSearch(
	provider: ethers.Provider,
	address: string,
	expectKeyID: string,
	label: string,
): Promise<SearchKeyRow> {
	for (let i = 0; i < 36; i++) {
		const row = await searchKey(provider, address)
		if (row.userPgpKeyID && row.userPublicKeyArmoredB64 && row.routePublicKeyArmoredB64) {
			const chain = row.userPgpKeyID.toUpperCase()
			if (chain && chain !== expectKeyID) {
				console.warn(
					`[warn] ${label} chain keyID ${chain.slice(0, 12)} ≠ local ${expectKeyID.slice(0, 12)}`,
				)
			}
			console.log(`[ok] ${label} searchKey route=${row.routeKeyID || '(empty)'}`)
			return row
		}
		await sleep(5000)
	}
	throw new Error(`${label} searchKey did not become live`)
}

async function main() {
	console.log(`RPC ${RPC}`)
	console.log(`out ${OUT_DIR}`)
	const openpgp = await loadOpenPgp()
	const provider = new ethers.JsonRpcProvider(RPC, 224422, { staticNetwork: true })

	const hosts = ['45', '98'] as const
	const ids: Record<string, Record<string, Identity>> = { '45': {}, '98': {} }
	const rows: Record<string, Record<string, SearchKeyRow>> = { '45': {}, '98': {} }

	for (const host of hosts) {
		const geth = await loadOrCreateIdentity(openpgp, `${host}-geth`, path.join(OUT_DIR, host, 'geth'))
		ids[host].geth = geth
		const existing = await searchKey(provider, geth.address)
		if (!existing.routeKeyID || !existing.routePublicKeyArmoredB64) {
			throw new Error(`${host}-geth is not on-chain; run lab-l0-register-routing.ts first`)
		}
		rows[host].geth = existing
		console.log(`[ok] ${host}-geth mailbox B=${existing.routeKeyID}`)
		for (const ch of CHANNELS.filter((c) => c.name !== 'geth')) {
			const id = await loadOrCreateIdentity(
				openpgp,
				`${host}-${ch.name}`,
				path.join(OUT_DIR, host, ch.name),
			)
			ids[host][ch.name] = id
			const sk = await searchKey(provider, id.address)
			if (sk.userPgpKeyID && sk.routePublicKeyArmoredB64) {
				console.log(`[ok] ${host}-${ch.name} already on-chain route=${sk.routeKeyID || '(empty)'}`)
			} else {
				await registerRoute(id, existing.routeKeyID)
			}
		}
	}

	for (const host of hosts) {
		for (const ch of CHANNELS) {
			rows[host][ch.name] = await pollSearch(
				provider,
				ids[host][ch.name].address,
				ids[host][ch.name].keyID,
				`${host}-${ch.name}`,
			)
		}
	}

	const peerOf: Record<(typeof hosts)[number], (typeof hosts)[number]> = { '45': '98', '98': '45' }
	for (const host of hosts) {
		const peer = peerOf[host]
		for (const ch of CHANNELS) {
			const dir = path.join(OUT_DIR, host, ch.name)
			const self = ids[host][ch.name]
			const sk = rows[host][ch.name]
			writeSecret(path.join(dir, 'routing.eth'), self.privateKey)
			writeSecret(path.join(dir, 'routing.key'), self.privateArmor)
			writeSecret(path.join(dir, 'self-user.asc'), self.publicArmor, 0o644)
			writeSecret(
				path.join(dir, 'self-mailbox-route.asc'),
				decodeArmorB64(sk.routePublicKeyArmoredB64),
				0o644,
			)
			const peerSk = rows[peer][ch.name]
			writeSecret(
				path.join(OUT_DIR, host, `peer-${ch.name}-user.asc`),
				decodeArmorB64(peerSk.userPublicKeyArmoredB64),
				0o644,
			)
			writeSecret(
				path.join(OUT_DIR, host, `peer-${ch.name}-route.asc`),
				decodeArmorB64(peerSk.routePublicKeyArmoredB64),
				0o644,
			)
		}
	}

	const summary: Record<string, unknown> = { rpc: RPC, channels: {} }
	for (const host of hosts) {
		;(summary.channels as Record<string, unknown>)[host] = Object.fromEntries(
			CHANNELS.map((ch) => [
				ch.name,
				{
					ports: ch.ports,
					routing_eoa: ids[host][ch.name].address,
					mailbox_b: rows[host][ch.name].routeKeyID,
					service: ch.service,
				},
			]),
		)
	}
	fs.writeFileSync(path.join(OUT_DIR, 'channels-summary.json'), `${JSON.stringify(summary, null, 2)}\n`)
	console.log('[ok] wrote channel key files + channels-summary.json (no private keys in summary)')
	console.log(JSON.stringify(summary, null, 2))
}

main().catch((err) => {
	console.error(err instanceof Error ? err.message : err)
	process.exit(1)
})
