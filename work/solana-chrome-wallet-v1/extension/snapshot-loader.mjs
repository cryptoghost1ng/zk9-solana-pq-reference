export async function loadSnapshotValidator() {
  const { default: initialize } = await import('./engine/snapshot.js');
  const api = await initialize({ module_or_path: new URL('./engine/snapshot_bg.wasm',import.meta.url) });
  return createSnapshotValidator(api);
}

// The injected API is always the real, pinned Wasm module in the application.
// Exporting this adapter also lets qualification exercise the production ABI.
export function createSnapshotValidator(api) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8',{ fatal:true });
  let poisoned = false;
  function invoke(request, operation) {
    if (poisoned) throw new Error('History engine stopped. Reopen the wallet.');
    const input = encoder.encode(JSON.stringify(request));
    if (!input.length || input.length > 64*1024*1024) throw new Error('History exceeds local wallet limits.');
    try {
      const address = api.zk9_input_alloc(input.length) >>> 0;
      if (!address || address + input.length > api.memory.buffer.byteLength) throw new Error('History input allocation failed.');
      new Uint8Array(api.memory.buffer,address,input.length).set(input);
      const code = operation==='selection' ? api.zk9_validate_selection()
        : operation==='deposit-intent' ? api.zk9_deposit_intent()
        : operation==='deposit' ? api.zk9_deposit_plan()
        : operation==='settlement' ? api.zk9_settlement_plan()
        : operation==='target' ? api.zk9_address(0) : operation==='address' ? api.zk9_address(1) : api.zk9_validate_snapshot();
      const length = api.zk9_output_len() >>> 0;
      const pointer = api.zk9_output_ptr() >>> 0;
      if (!length || length > 128*1024*1024 || pointer + length > api.memory.buffer.byteLength) throw new Error('Invalid history result size.');
      const output = new Uint8Array(api.memory.buffer,pointer,length);
      const result = JSON.parse(decoder.decode(output));
      if (code !== 1 || result.ok !== true) throw new Error('Pool history failed local validation.');
      return operation==='selection' ? { snapshot:result.snapshot, paths:result.paths, ...(result.anchor?{anchor:result.anchor}:{}) }
        : ['target','address','deposit','deposit-intent','settlement'].includes(operation) ? result.result : result.snapshot;
    } catch (error) {
      if (error instanceof WebAssembly.RuntimeError) poisoned = true;
      throw error;
    } finally { input.fill(0); if (!poisoned) api.zk9_clear(); }
  }
  const validate = request => invoke(request, 'snapshot');
  // Inputs remain raw accounts. No caller can supply an authoritative root or
  // path; selection re-runs the complete snapshot validation inside Wasm.
  validate.select = request => invoke(request, 'selection');
  validate.target = request => invoke(request, 'target');
  validate.address = request => invoke(request, 'address');
  validate.deposit = request => invoke(request, 'deposit');
  validate.depositIntent = request => invoke(request, 'deposit-intent');
  validate.settlement = request => invoke(request, 'settlement');
  return validate;
}
