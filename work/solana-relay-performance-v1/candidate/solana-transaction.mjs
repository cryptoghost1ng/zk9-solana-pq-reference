// Private custody transport primitives, ported from the native publisher.
// This module does NOT authorize an instruction. The deposit/payment adapter
// must bind it to an approved, durable operation before signing or broadcasting.
import { requireState, integer } from './checkpoint.mjs';
import { un58, toBase64, fromBase64, hex } from './payment-wire.mjs';
export { un58, toBase64, fromBase64, hex };
const encoder = new TextEncoder(), alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function b58(bytes) {
  requireState(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 64);
  let n = 0n, result = '';
  for (const b of bytes) n = n * 256n + BigInt(b);
  while (n) { result = alphabet[Number(n % 58n)] + result; n /= 58n; }
  for (const b of bytes) { if (b) break; result = '1' + result; }
  return result;
}
export function concat(...parts) {
  requireState(parts.every(x => x instanceof Uint8Array));
  const result = new Uint8Array(parts.reduce((n, x) => n + x.length, 0));
  let at = 0; for (const part of parts) { result.set(part, at); at += part.length; } return result;
}
// Same public-byte comparison and early-exit behavior; not constant time.
export function equalBytes(a,b) {
  if(!(a instanceof Uint8Array)||!(b instanceof Uint8Array)||a.length!==b.length)return false;
  for(let i=0;i<a.length;i++)if(a[i]!==b[i])return false;
  return true;
}
export function u32(n) { requireState(Number.isInteger(n) && n >= 0 && n <= 0xffffffff); const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; }
export function u64(n) { n = BigInt(n); requireState(n >= 0n && n < 2n ** 64n); const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n, true); return b; }
export const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const budget = un58('ComputeBudget111111111111111111111111111111', 32);
const memoProgram = un58('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', 32);
export const COMPUTE_LIMIT = 1400000;
const vector = n => {
  requireState(Number.isInteger(n) && n >= 0 && n < 65536);
  const out = []; do { let b = n & 127; n >>>= 7; if (n) b |= 128; out.push(b); } while (n);
  return Uint8Array.from(out);
};
function checkedInstruction(ix) {
  requireState(ix && Object.keys(ix).sort().join(',') === 'accounts,data,program'
    && ix.program instanceof Uint8Array && ix.program.length === 32 && ix.data instanceof Uint8Array
    && ix.data.length < 65536 && Array.isArray(ix.accounts) && ix.accounts.length <= 32, 'Invalid transaction instruction.');
  for (const a of ix.accounts) requireState(a && Object.keys(a).sort().join(',') === 'pub,signer,writable'
    && a.pub instanceof Uint8Array && a.pub.length === 32 && typeof a.signer === 'boolean' && typeof a.writable === 'boolean');
  return structuredClone(ix);
}
export function instructionEqual(a, b) {
  return equalBytes(a.program, b.program) && equalBytes(a.data, b.data) && a.accounts.length === b.accounts.length
    && a.accounts.every((x, i) => equalBytes(x.pub, b.accounts[i].pub) && x.signer === b.accounts[i].signer && x.writable === b.accounts[i].writable);
}
// Same domain-separated HKDF expansion as native deposit.public_signing_seed.
export async function publicSigningSeed(seed) {
  requireState(seed instanceof Uint8Array && seed.length === 32 && seed.some(x => x));
  const mac = async (key, data) => {
    const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
  };
  const copy = seed.slice(); let prk;
  try {
    const salt = await sha256(encoder.encode('ZK9/SOLANA/PUBLIC-WALLET/EXTRACT/v1\0'));
    prk = await mac(salt, copy);
    return await mac(prk, encoder.encode('ZK9/SOLANA/PUBLIC-WALLET/EXPAND/v1\0\x01'));
  } finally { copy.fill(0); prk?.fill(0); }
}
export async function privateSigner(seed) {
  requireState(seed instanceof Uint8Array && seed.length === 32 && seed.some(x => x));
  const pkcs8 = concat(Uint8Array.from([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32]), seed);
  let jwk;
  try {
    // WebCrypto has no getPublicKey(privateKey) API. This temporary export is
    // confined to custody; only the final nonextractable signing key survives.
    const temporary = await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']);
    jwk = await crypto.subtle.exportKey('jwk', temporary);
    requireState(typeof jwk.x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(jwk.x));
    const pub = fromBase64(jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '=', 32);
    jwk.d = '';
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', false, ['sign']);
    return Object.freeze({ get pub() { return pub.slice(); }, async sign(message) {
      requireState(message instanceof Uint8Array && message.length > 0 && message.length <= 1232);
      return new Uint8Array(await crypto.subtle.sign('Ed25519', key, message));
    } });
  } finally { pkcs8.fill(0); if (jwk) jwk.d = ''; }
}
export async function signedTransaction(authority, instructions, extraSigners, blockhash, lastValidHeight) {
  integer(lastValidHeight); const hash = un58(blockhash, 32);
  requireState(Array.isArray(instructions) && instructions.length >= 1 && instructions.length <= 2 && Array.isArray(extraSigners));
  const entries = new Map();
  const add = (pub, signer, writable) => {
    requireState(pub instanceof Uint8Array && pub.length === 32);
    const name = b58(pub), old = entries.get(name);
    entries.set(name, { pub: pub.slice(), signer: !!signer || !!old?.signer, writable: !!writable || !!old?.writable });
  };
  add(authority.pub, true, true);
  const all = [{ program: budget, accounts: [], data: concat(Uint8Array.of(2), u32(COMPUTE_LIMIT)) },
    ...instructions.map(checkedInstruction),
    { program: memoProgram, accounts: [], data: encoder.encode('ZK9 ' + hex(crypto.getRandomValues(new Uint8Array(4)))) }];
  for (const ix of all) { for (const a of ix.accounts) add(a.pub, a.signer, a.writable); add(ix.program, false, false); }
  const group = a => a.signer ? (a.writable ? 0 : 1) : (a.writable ? 2 : 3);
  const keys = [...entries.values()].sort((a, b) => group(a) - group(b)); requireState(keys.length <= 32);
  const signing = keys.filter(a => a.signer), signers = [authority, ...extraSigners];
  requireState(signing.length >= 1 && signing.length <= 3 && equalBytes(signing[0].pub, authority.pub));
  requireState(new Set(signers.map(s => b58(s.pub))).size === signers.length && signing.length === signers.length);
  const index = pub => keys.findIndex(a => equalBytes(a.pub, pub));
  const header = Uint8Array.of(signing.length, signing.filter(k => !k.writable).length, keys.filter(k => !k.signer && !k.writable).length);
  const body = concat(header, vector(keys.length), ...keys.map(k => k.pub), hash, vector(all.length),
    ...all.map(ix => concat(Uint8Array.of(index(ix.program)), vector(ix.accounts.length), Uint8Array.from(ix.accounts.map(a => index(a.pub))), vector(ix.data.length), ix.data)));
  const sigs = [];
  for (const entry of signing) {
    const signer = signers.find(s => equalBytes(s.pub, entry.pub)); requireState(signer, 'Unexpected signing authority.');
    const signature = await signer.sign(body); requireState(signature instanceof Uint8Array && signature.length === 64); sigs.push(signature);
  }
  const bytes = concat(vector(sigs.length), ...sigs, body); requireState(bytes.length <= 1232, 'Transaction exceeds packet size.');
  return Object.freeze({ raw: toBase64(bytes), signature: b58(sigs[0]), last_valid_height: lastValidHeight, limit: COMPUTE_LIMIT, wire_bytes: bytes.length });
}
export async function decodeTransaction(raw) {
  const bytes = fromBase64(raw, 1232); let at = 0;
  const take = n => { requireState(Number.isInteger(n) && n >= 0 && at + n <= bytes.length, 'Truncated transaction.'); const b = bytes.subarray(at, at + n); at += n; return b; };
  const length = () => {
    let n = 0, shift = 0, start = at;
    for (let i = 0; i < 3; i++) { const b = take(1)[0]; n |= (b & 127) << shift; if (!(b & 128)) { requireState(equalBytes(vector(n), bytes.subarray(start, at)), 'Noncanonical vector.'); return n; } shift += 7; }
    throw new Error('Oversized transaction vector.');
  };
  const count = length(); requireState(count >= 1 && count <= 3);
  const sigs = Array.from({ length: count }, () => take(64)), start = at, header = take(3);
  requireState(header[0] === count && header[1] < count);
  const keyCount = length(); requireState(keyCount >= count && keyCount <= 32 && header[2] <= keyCount - count);
  const keys = Array.from({ length: keyCount }, () => take(32)); requireState(new Set(keys.map(b58)).size === keyCount);
  const blockhash = b58(take(32)), ixCount = length(); requireState(ixCount >= 3 && ixCount <= 4);
  const key = i => { requireState(i < keys.length); return keys[i]; };
  const instructions = Array.from({ length: ixCount }, () => {
    const program = key(take(1)[0]), n = length(); requireState(n <= 32);
    const accounts = Array.from(take(n), i => ({ pub: key(i), signer: i < count, writable: i < count ? i < count - header[1] : i < keyCount - header[2] }));
    return { program, accounts, data: take(length()) };
  });
  requireState(at === bytes.length, 'Trailing transaction bytes.');
  for (let i = 0; i < count; i++) {
    const publicKey = await crypto.subtle.importKey('raw', keys[i], 'Ed25519', false, ['verify']);
    requireState(await crypto.subtle.verify('Ed25519', publicKey, sigs[i], bytes.subarray(start)), 'Invalid stored signature.');
  }
  requireState(instructionEqual(instructions[0], { program: budget, accounts: [], data: concat(Uint8Array.of(2), u32(COMPUTE_LIMIT)) }), 'Unexpected compute budget.');
  const memo = instructions.at(-1);
  requireState(equalBytes(memo.program, memoProgram) && memo.accounts.length === 0 && /^ZK9 [0-9a-f]{8}$/.test(new TextDecoder('utf-8', { fatal: true }).decode(memo.data)), 'Unexpected memo.');
  return { authority: keys[0].slice(), signers: keys.slice(0, count).map(k => k.slice()), signature: b58(sigs[0]), blockhash, instructions: instructions.slice(1, -1) };
}
