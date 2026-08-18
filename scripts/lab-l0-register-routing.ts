#!/usr/bin/env npx tsx
/**
 * Lab-only: create dedicated routing EOAs + OpenPGP keys, pick mailbox B,
 * POST /api/regiestChatRoute, poll AddressPGP.searchKey, write host key files.
 * Does not log private keys or full armor. Does not invent SI commands.
 *
 * Run from the BeamioContract repo root:
 *   npx tsx src/conet-l0d/scripts/lab-l0-register-routing.ts
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
const GUARDIAN_NODES = '0xBC6b53065b5647261396d002bDBA0d3396E0722f'
const REGISTER_URL = process.env.REGIEST_URL || 'https://beamio.app/api/regiestChatRoute'
const OUT_DIR = process.env.LAB_L0_OUT || path.join(CRATE, 'lab-secrets')

const FALLBACK_DOMAINS = [
	'9977E9A45187DD80',
	'B4CB0A41352E9BDF',
	'20AB90FE82D0E9E3',
	'AE85A2AEEC768225',
	'F8117E1568EEAED7',
] as const

type OpenPgpMod = typeof import('openpgp')

type SearchKeyRow = {
	userPgpKeyID: string
	userPublicKeyArmoredB64: string
	routeKeyID: string
	routePublicKeyArmoredB64: string
	routeOnline: boolean
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms))
}

function normDomain(raw: unknown): string {
	return String(raw ?? '')
		.trim()
		.replace(/\.conet\.network$/i, '')
		.toUpperCase()
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
		routeOnline: Boolean(sk[4]),
	}
}

async function fetchGuardianDomains(provider: ethers.Provider): Promise<string[]> {
	const abi = [
		'function getAllNodes(uint256 start,uint256 length) view returns (tuple(uint256 id,string PGP,string PGPKey,string ip_addr,string regionName)[])',
	]
	const c = new ethers.Contract(GUARDIAN_NODES, abi, provider)
	try {
		const pages = await Promise.all([
			c.getAllNodes(0, 400) as Promise<unknown[]>,
			c.getAllNodes(400, 400) as Promise<unknown[]>,
		])
		const domains = Array.from(
			new Set(
				pages
					.flat()
					.map((node) =>
						normDomain(
							(node as { PGPKey?: unknown })?.PGPKey ?? (node as readonly unknown[])?.[2],
						),
					)
					.filter((d): d is string => Boolean(d)),
			),
		)
		if (domains.length) return domains
	} catch (e) {
		console.warn('[warn] getAllNodes failed:', e instanceof Error ? e.message : String(e))
	}
	return [...FALLBACK_DOMAINS]
}

async function probeEntry(domain: string): Promise<{ domain: string; ok: boolean; url: string; status?: number }> {
	for (const scheme of ['https', 'http'] as const) {
		const url = `${scheme}://${domain.toLowerCase()}.conet.network/post`
		try {
			const res = await fetch(url, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({
					data: '-----BEGIN PGP MESSAGE-----\n\nYm9keSBoYXMgbm90IFBHUCBtZXNzYWdl\n-----END PGP MESSAGE-----',
				}),
				signal: AbortSignal.timeout(6000),
			})
			const text = await res.text().catch(() => '')
			const ok =
				res.status === 404 ||
				/body has not PGP message/i.test(text) ||
				res.status === 200 ||
				res.status === 400
			if (ok) return { domain, ok: true, url: `${scheme}://${domain.toLowerCase()}.conet.network`, status: res.status }
		} catch {
			/* try next scheme */
		}
	}
	return { domain, ok: false, url: `https://${domain.toLowerCase()}.conet.network` }
}

async function generateIdentity(openpgp: OpenPgpMod, label: string) {
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

async function registerRoute(id: Awaited<ReturnType<typeof generateIdentity>>, routeKeyID: string) {
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

async function loadOrCreateIdentity(
	openpgp: OpenPgpMod,
	label: string,
	dir: string,
): Promise<Awaited<ReturnType<typeof generateIdentity>>> {
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

function decodeArmorB64(raw: string): string {
	const t = raw.trim()
	if (t.includes('BEGIN PGP')) return t
	return Buffer.from(t, 'base64').toString('utf8')
}

function writeSecret(file: string, contents: string, mode = 0o600) {
	fs.mkdirSync(path.dirname(file), { recursive: true })
	fs.writeFileSync(file, contents.endsWith('\n') ? contents : `${contents}\n`, { mode })
	fs.chmodSync(file, mode)
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
				console.warn(`[warn] ${label} chain keyID ${chain.slice(0, 12)} ≠ local ${expectKeyID.slice(0, 12)}`)
			}
			console.log(`[ok] ${label} searchKey route=${row.routeKeyID || '(empty)'}`)
			return row
		}
		await sleep(5000)
	}
	throw new Error(`${label} searchKey did not become live`)
}

function firstNot(healthy: string[], banned: string): string {
	const hit = healthy.find((d) => d !== banned)
	if (!hit) throw new Error(`no healthy Guardian domain other than ${banned}`)
	return hit
}

async function main() {
	console.log(`RPC ${RPC}`)
	console.log(`out ${OUT_DIR}`)
	const openpgp = await loadOpenPgp()
	const provider = new ethers.JsonRpcProvider(RPC, 224422, { staticNetwork: true })
	const domains = await fetchGuardianDomains(provider)
	console.log(`[ok] guardian domains ${domains.length}`)

	const probes: { domain: string; ok: boolean; url: string; status?: number }[] = []
	for (const domain of domains.slice(0, 24)) {
		const p = await probeEntry(domain)
		probes.push(p)
		if (p.ok) console.log(`[ok] entry ${p.url} status=${p.status ?? '?'}`)
		if (probes.filter((x) => x.ok).length >= 8) break
	}
	const healthy = probes.filter((p) => p.ok).map((p) => p.domain)
	if (healthy.length < 2) throw new Error(`need ≥2 healthy Guardian domains, got ${healthy.length}`)
	const b45 = healthy[0]
	const b98 = healthy[1]
	const extra = healthy.filter((d) => d !== b45 && d !== b98)
	const a45 = extra[0] || firstNot(healthy, b98)
	const c45 = extra[1] || extra[0] || firstNot(healthy, b45)
	const a98 = extra[0] || firstNot(healthy, b45)
	const c98 = extra[1] || extra[0] || firstNot(healthy, b98)
	const urlOf = (d: string) =>
		probes.find((p) => p.domain === d && p.ok)?.url || `https://${d.toLowerCase()}.conet.network`

	const dir45 = path.join(OUT_DIR, '45')
	const dir98 = path.join(OUT_DIR, '98')
	const id45 = await loadOrCreateIdentity(openpgp, '45', dir45)
	const id98 = await loadOrCreateIdentity(openpgp, '98', dir98)

	const existing45 = await searchKey(provider, id45.address)
	if (existing45.userPgpKeyID && existing45.routePublicKeyArmoredB64) {
		console.log(`[ok] 45 already on-chain route=${existing45.routeKeyID || '(empty)'}`)
	} else {
		await registerRoute(id45, b45)
	}
	await sleep(12_000)
	const existing98 = await searchKey(provider, id98.address)
	if (existing98.userPgpKeyID && existing98.routePublicKeyArmoredB64) {
		console.log(`[ok] 98 already on-chain route=${existing98.routeKeyID || '(empty)'}`)
	} else {
		await registerRoute(id98, b98)
	}
	const sk45 = await pollSearch(provider, id45.address, id45.keyID, '45')
	const sk98 = await pollSearch(provider, id98.address, id98.keyID, '98')

	writeSecret(path.join(dir45, 'routing.eth'), id45.privateKey)
	writeSecret(path.join(dir45, 'routing.key'), id45.privateArmor)
	writeSecret(path.join(dir45, 'self-user.asc'), id45.publicArmor, 0o644)
	writeSecret(path.join(dir45, 'self-mailbox-route.asc'), decodeArmorB64(sk45.routePublicKeyArmoredB64), 0o644)
	writeSecret(path.join(dir45, 'peer-user.asc'), decodeArmorB64(sk98.userPublicKeyArmoredB64), 0o644)
	writeSecret(path.join(dir45, 'peer-route.asc'), decodeArmorB64(sk98.routePublicKeyArmoredB64), 0o644)

	writeSecret(path.join(dir98, 'routing.eth'), id98.privateKey)
	writeSecret(path.join(dir98, 'routing.key'), id98.privateArmor)
	writeSecret(path.join(dir98, 'self-user.asc'), id98.publicArmor, 0o644)
	writeSecret(path.join(dir98, 'self-mailbox-route.asc'), decodeArmorB64(sk98.routePublicKeyArmoredB64), 0o644)
	writeSecret(path.join(dir98, 'peer-user.asc'), decodeArmorB64(sk45.userPublicKeyArmoredB64), 0o644)
	writeSecret(path.join(dir98, 'peer-route.asc'), decodeArmorB64(sk45.routePublicKeyArmoredB64), 0o644)

	const summary = {
		rpc: RPC,
		addressPgp: ADDRESS_PGP,
		'45': {
			routing_eoa: id45.address,
			mailbox_b: sk45.routeKeyID || b45,
			entries: [urlOf(a45)],
			listen_entries: [urlOf(c45)],
		},
		'98': {
			routing_eoa: id98.address,
			mailbox_b: sk98.routeKeyID || b98,
			entries: [urlOf(a98)],
			listen_entries: [urlOf(c98)],
		},
	}
	fs.writeFileSync(path.join(OUT_DIR, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`)
	console.log('[ok] wrote key files + summary.json (no private keys in summary)')
	console.log(JSON.stringify(summary, null, 2))
}

main().catch((err) => {
	console.error(err instanceof Error ? err.message : err)
	process.exit(1)
})
