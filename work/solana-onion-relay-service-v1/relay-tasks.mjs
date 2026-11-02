// Task manager of the relay service: admits at most one sponsored payment at a time, keeps it running after the
// HTTP reply, and reopens it from durable state after a failure or a restart. It owns no keys and no network; the
// sponsor, the journal and the chain are behind `openTask`. Nothing here reports progress to a caller.
import {requireState as require,integer} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
import {VERSION} from '../solana-private-relay-v1/relay-request.mjs';

export class RelayRefusal extends Error {
  constructor(code) { super(code); this.name = 'RelayRefusal'; this.code = code; }
}
export const DEFAULT_POLICY = Object.freeze({
  pauseMs: 150, backoffMs: Object.freeze([2000, 4000, 8000, 16000]), maxConsecutiveFailures: 5,
  deadlineMs: 4 * 60 * 60 * 1000, progressEvery: 100,
});
// The reply carries no state on purpose: whoever can submit learns nothing about progress, and the wallet never
// trusts a relay status anyway (settlement is read back from validated pool history).
const ACCEPTED = Object.freeze({ version: VERSION, verified: true, published: false, settled: false });
const defaultSleep = (ms, signal) => new Promise(resolve => {
  if (signal?.aborted) return resolve();
  const timer = setTimeout(done, ms);
  function done() { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve(); }
  signal?.addEventListener('abort', done, { once: true });
});

export function createTaskManager({ context, readRequest, openTask, store, emit = () => {}, sleep = defaultSleep, now = () => Date.now(), policy = DEFAULT_POLICY }) {
  require(typeof readRequest === 'function' && typeof openTask === 'function' && store && typeof store.save === 'function', 'Task manager dependencies required.');
  integer(policy.pauseMs); integer(policy.maxConsecutiveFailures); integer(policy.deadlineMs); integer(policy.progressEvery);
  require(policy.maxConsecutiveFailures > 0 && policy.progressEvery > 0 && policy.backoffMs.length > 0, 'Invalid relay task policy.');
  const lifetime = new AbortController();
  const parked = new Map();
  let admitting = false, stopped = false, active = null;
  const tell = event => { try { emit(event); } catch { /* an observer must never stop the relay */ } };

  function park(entry, reason) {
    parked.set(entry.id, reason);
    tell({ type: 'parked', id: entry.id, reason });
  }
  async function run(entry) {
    let failures = 0, announced = null;
    try {
      while (!stopped) {
        if (now() - entry.startedAt > policy.deadlineMs) { park(entry, 'deadline'); return; }
        try {
          entry.task ??= await openTask(entry.raw, lifetime.signal);
          require(entry.task.id === entry.id, 'Reopened task is for another request.');
          const result = await entry.task.step();
          failures = 0; entry.steps++; entry.state = result.state;
          const notable = ['verified', 'awaiting_receipt'].includes(result.state) && announced !== result.state;
          if (notable) announced = result.state; else if (!['verified', 'awaiting_receipt'].includes(result.state)) announced = null;
          if (entry.steps % policy.progressEvery === 0 || notable)
            tell({ type: 'progress', id: entry.id, kind: entry.kind, steps: entry.steps, state: result.state, elapsed_ms: now() - entry.startedAt });
          if (result.state === 'settled' || result.state === 'conflicted') {
            // The outcome is durable before the task is announced as finished.
            store.finish(entry.id, result.state);
            tell({ type: 'finished', id: entry.id, kind: entry.kind, state: result.state, steps: entry.steps, elapsed_ms: now() - entry.startedAt });
            return;
          }
          // Confirmed effects were already reconciled: continue at once. Pending and quiet states back off.
          if (!['step_confirmed', 'verified'].includes(result.state)) await sleep(policy.pauseMs, lifetime.signal);
        } catch (error) {
          if (stopped) return;
          // A failure may have left an uncertain send. The journal decides on reopening; never keep using the failed task.
          try { entry.task?.close(); } catch { /* already closed */ }
          entry.task = null; failures++;
          tell({ type: 'task_error', id: entry.id, failures, message: String(error?.message ?? error).slice(0, 200) });
          if (failures >= policy.maxConsecutiveFailures) { park(entry, 'failures'); return; }
          await sleep(policy.backoffMs[Math.min(failures - 1, policy.backoffMs.length - 1)], lifetime.signal);
        }
      }
    } finally {
      try { entry.task?.close(); } catch { /* already closed */ }
      entry.task = null;
      if (active === entry) active = null;
    }
  }
  function start(entry) {
    active = entry;
    entry.loop = run(entry);
  }
  const entryFor = (request, raw, task) => ({ id: request.id, kind: request.kind, raw, task, steps: 0, state: null, startedAt: now(), loop: null });

  return Object.freeze({
    async submit(raw) {
      if (stopped) return { status: 503, body: { error: 'stopping' } };
      if (admitting) return { status: 429, body: { error: 'busy' } };
      admitting = true;
      try {
        let request;
        try { request = await readRequest(raw, context); } catch { tell({ type: 'refused', code: 'malformed' }); return { status: 400, body: { error: 'rejected' } }; }
        // Idempotent: a wallet that lost the reply may submit the same approved proof again; nothing new starts.
        if (store.outcome(request.id) !== null || active?.id === request.id) { tell({ type: 'duplicate', id: request.id }); return { status: 200, body: ACCEPTED }; }
        if (active) { tell({ type: 'refused', code: 'busy' }); return { status: 429, body: { error: 'busy' } }; }
        let task;
        try { task = await openTask(raw, lifetime.signal); }
        catch (error) {
          if (error instanceof RelayRefusal) { tell({ type: 'refused', code: error.code }); return { status: 422, body: { error: error.code } }; }
          tell({ type: 'refused', code: 'open_failed', message: String(error?.message ?? error).slice(0, 200) });
          return { status: 400, body: { error: 'rejected' } };
        }
        if (stopped) { try { task.close(); } catch { /* closed */ } return { status: 503, body: { error: 'stopping' } }; }
        try { require(task.id === request.id, 'Opened task is for another request.'); store.save(request.id, raw); }
        catch (error) { try { task.close(); } catch { /* closed */ } tell({ type: 'refused', code: 'not_persisted', message: String(error?.message ?? error).slice(0, 200) }); return { status: 400, body: { error: 'rejected' } }; }
        parked.delete(request.id);
        start(entryFor(request, raw, task));
        tell({ type: 'admitted', id: request.id, kind: request.kind, wire_bytes: request.wire.length, transport: task.transport });
        return { status: 200, body: ACCEPTED };
      } finally { admitting = false; }
    },
    // After a restart: reopen the single unfinished request from durable state (the supervisor retries the open itself).
    async recover() {
      const ids = store.unfinished();
      require(ids.length <= 1, 'More than one unfinished relay request; refusing to guess.');
      if (ids.length === 0) return null;
      const raw = store.load(ids[0]), request = await readRequest(raw, context);
      require(request.id === ids[0], 'Stored relay request does not match its name.');
      start(entryFor(request, raw, null));
      tell({ type: 'recovered', id: request.id, kind: request.kind });
      return request.id;
    },
    status() {
      return { active: active ? { id: active.id, kind: active.kind, steps: active.steps, state: active.state } : null, parked: [...parked] };
    },
    async stop() {
      stopped = true; lifetime.abort();
      if (active) await active.loop;
    },
  });
}
