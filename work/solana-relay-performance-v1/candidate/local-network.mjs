// Fixed local-validator profile, not a public-network light client. Profile
// construction belongs to trusted extension configuration, never to a webpage.
import { requireState, integer } from './checkpoint.mjs';
import { un58, fromBase64, digest } from './payment-wire.mjs';
import { b58 } from './solana-transaction.mjs';
const LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111';
const MAX_RESPONSE = 64 * 1024 * 1024;
const METHODS = new Set(['getGenesisHash', 'getVersion', 'getAccountInfo', 'getProgramAccounts', 'getLatestBlockhash',
  'getSignatureStatuses', 'getBlockHeight', 'sendTransaction', 'requestAirdrop', 'getBalance',
  'getMinimumBalanceForRentExemption', 'simulateTransaction', 'getTransaction', 'getHealth',
  'getTokenAccountsByOwner', 'getSlot', 'getFeeForMessage']);
export function checkedNetwork(value) {
  requireState(value && Object.keys(value).sort().join(',') === 'endpoint,genesis,programs,scope,version');
  const url = new URL(value.endpoint);
  requireState(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port && url.pathname === '/'
    && !url.search && !url.hash && !url.username && !url.password && value.endpoint === url.origin + '/', 'Only the configured loopback RPC is supported.');
  requireState(value.scope === 'isolated-solana-validator-synthetic-only' && value.version === '3.1.10', 'Unsupported local validator.');
  un58(value.genesis, 32);
  requireState(value.programs && typeof value.programs === 'object' && !Array.isArray(value.programs)
    && Object.keys(value.programs).length >= 1 && Object.keys(value.programs).length <= 10);
  for (const [key, hash] of Object.entries(value.programs)) { un58(key, 32); requireState(typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash)); }
  return structuredClone(value);
}
export class LocalNetwork {
  #profile; #fetch; #signal; #id = 0; #programData = new Map(); #epoch = 0;
  // Content verification cache, NOT a cached RPC attestation. Every attest()
  // still checks ledger/version and freshly reads BOTH loader accounts.
  // Immutable profile + same address + byte-for-byte canonical encoding means
  // the very same executable already passed all header and SHA-256 checks.
  #codeCache = new Map();
  // Browser fetch requires its Window/Worker receiver, not this adapter.
  constructor({ profile, signal, fetchImpl = globalThis.fetch.bind(globalThis) }) { this.#profile = checkedNetwork(profile); this.#fetch = fetchImpl; this.#signal = signal; }
  get profile() { return structuredClone(this.#profile); }
  invalidate() { this.#epoch++; this.#programData.clear(); }
  async rpc(method, params = []) {
    this.#signal?.throwIfAborted(); const epoch = this.#epoch, id = ++this.#id;
    requireState(METHODS.has(method) && Array.isArray(params), 'Unsupported local RPC method.');
    const timeout = AbortSignal.timeout(15000), signal = this.#signal ? AbortSignal.any([this.#signal, timeout]) : timeout;
    const response = await this.#fetch(this.#profile.endpoint, { method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id, method, params }), signal });
    requireState(response.status === 200, 'Local RPC is unavailable.');
    const contentLength = response.headers.get('content-length');
    if (contentLength !== null) requireState(/^\d+$/.test(contentLength) && Number(contentLength) <= MAX_RESPONSE, 'RPC response is too large.');
    requireState(response.body, 'Missing RPC response.');
    const reader = response.body.getReader(), chunks = []; let total = 0;
    try {
      for (;;) { const { done, value } = await reader.read(); if (done) break; total += value.length;
        requireState(total <= MAX_RESPONSE, 'RPC response is too large.'); chunks.push(value); }
    } catch (error) { await reader.cancel().catch(() => {}); throw error; }
    finally { reader.releaseLock(); }
    const bytes = new Uint8Array(total); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    requireState(epoch === this.#epoch, 'Network session changed.'); this.#signal?.throwIfAborted();
    requireState(value && value.jsonrpc === '2.0' && value.id === id, 'RPC response does not match the request.');
    if (Object.hasOwn(value, 'error')) {
      const error = new Error('Local RPC rejected ' + method + '.');
      if (Number.isSafeInteger(value.error?.code)) error.rpcCode = value.error.code;
      throw error;
    }
    requireState(Object.hasOwn(value, 'result'), 'Missing RPC result.'); return value.result;
  }
  async account(pub, minSlot) {
    if (pub instanceof Uint8Array) pub = b58(pub); un58(pub, 32);
    if (minSlot !== undefined) integer(minSlot);
    const response = await this.rpc('getAccountInfo', [pub, { encoding: 'base64', commitment: 'confirmed', ...(minSlot === undefined ? {} : { minContextSlot: minSlot }) }]);
    integer(response?.context?.slot);
    requireState(minSlot === undefined || response.context.slot >= minSlot, 'RPC returned an older account.');
    requireState(Object.hasOwn(response, 'value')); return response.value;
  }
  async checkLedger() {
    try {
      requireState(await this.rpc('getGenesisHash') === this.#profile.genesis, 'Local ledger changed.');
      requireState((await this.rpc('getVersion'))?.['solana-core'] === this.#profile.version, 'Local validator version changed.');
    } catch (error) { this.invalidate(); throw error; }
  }
  async attest(programs) {
    this.invalidate(); const epoch = this.#epoch, verified = new Map();
    requireState(Array.isArray(programs) && programs.length > 0 && new Set(programs).size === programs.length);
    await this.checkLedger();
    for (const pub of programs) {
      un58(pub, 32); const expected = this.#profile.programs[pub]; requireState(expected, 'Unpinned local program.');
      const account = await this.account(pub);
      requireState(account?.executable === true && account.owner === LOADER && account.data?.[1] === 'base64', 'Invalid executable account.');
      const bytes = fromBase64(account.data[0], 36);
      requireState(bytes.length === 36 && new DataView(bytes.buffer).getUint32(0, true) === 2, 'Wrong program loader state.');
      const address = b58(bytes.subarray(4)), code = await this.account(address);
      requireState(code?.executable === false && code.owner === LOADER && code.data?.[1] === 'base64', 'Invalid program data account.');
      const cached = this.#codeCache.get(pub);
      if (!cached || cached.address !== address || cached.raw !== code.data[0]) {
        this.#codeCache.delete(pub);
        const executable = fromBase64(code.data[0], 16 * 1024 * 1024);
        requireState(executable.length > 45 && new DataView(executable.buffer).getUint32(0, true) === 3 && executable[12] === 0, 'Program must be immutable.');
        requireState(await digest(executable.subarray(45)) === expected, 'Program code differs from the configured version.');
        this.#codeCache.set(pub, { address, raw: code.data[0] });
      }
      verified.set(pub, address);
    }
    requireState(epoch === this.#epoch, 'Attestation was invalidated.'); this.#programData = verified;
    return Object.freeze({ genesis: this.#profile.genesis, programs: Object.fromEntries(verified), rpc_consensus_authenticated: false });
  }
  requireProgram(pub) { requireState(this.#programData.has(pub), 'Attest the local program first.'); return this.#programData.get(pub); }
  async history(program, minSlot = 0) {
    this.requireProgram(program); integer(minSlot);
    await this.checkLedger(); this.requireProgram(program);
    const response = await this.rpc('getProgramAccounts', [program, { encoding: 'base64', commitment: 'confirmed', withContext: true, minContextSlot: minSlot }]);
    integer(response?.context?.slot); requireState(response.context.slot >= minSlot && Array.isArray(response.value), 'Invalid or stale pool history.');
    // Caller MUST run the raw Rust validator and custody scanner over this.
    return response;
  }
}
