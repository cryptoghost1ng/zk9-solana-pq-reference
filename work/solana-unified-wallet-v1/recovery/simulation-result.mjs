// RPC diagnostics are untrusted. Only a specific runtime exhaustion on the
// expected instruction/program permits smaller work; custom errors never do.
export function computeExhausted(result, program, instruction = 1) {
  const error = result?.err?.InstructionError;
  if (!Array.isArray(error) || error.length !== 2 || error[0] !== instruction) return false;
  if (error[1] === 'ComputationalBudgetExceeded') return true;
  if (error[1] !== 'ProgramFailedToComplete' || result.unitsConsumed !== 1400000
      || !Array.isArray(result.logs) || result.logs.length > 256) return false;
  return result.logs.includes(`Program ${program} failed: exceeded CUs meter at BPF instruction`);
}

// A verifier transaction is budget + verifier + the locally generated memo.
// The verifier can succeed while leaving too little CU for that final memo.
// Only this known layout and ordered runtime evidence allow reducing work;
// account creation and arbitrary instruction-2 errors must still fail closed.
export function publicationComputeExhausted(result, program, verifierStep = false) {
  if (computeExhausted(result, program)) return true;
  const memo = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
  if (!verifierStep || !computeExhausted(result, memo, 2)
      || result?.err?.InstructionError?.[1] !== 'ProgramFailedToComplete') return false;
  const logs = result.logs;
  const success = logs.indexOf(`Program ${program} success`);
  const invoke = logs.indexOf(`Program ${memo} invoke [1]`);
  const failure = logs.indexOf(`Program ${memo} failed: exceeded CUs meter at BPF instruction`);
  return success >= 0 && invoke > success && failure > invoke
    && !logs.some(line => line.startsWith(`Program ${program} failed:`));
}

export function simulationFailure(result, step) {
  const error = result?.err?.InstructionError;
  const at = Array.isArray(error) && Number.isSafeInteger(error[0]) ? error[0] : '?';
  const code = Array.isArray(error) && typeof error[1] === 'string' && /^[A-Za-z]{1,64}$/.test(error[1])
    ? error[1] : Array.isArray(error) && Number.isSafeInteger(error[1]?.Custom) ? `Custom(${error[1].Custom})` : 'RPC rejection';
  const units = Number.isSafeInteger(result?.unitsConsumed) ? result.unitsConsumed : '?';
  return `Proof simulation rejected the instruction. Step ${step}; instruction ${at}; ${code}; CU ${units}.`;
}
