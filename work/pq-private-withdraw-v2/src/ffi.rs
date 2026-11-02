//! In-process verification boundary for the native keeper. No ledger or prover API.
use std::{panic::{catch_unwind,AssertUnwindSafe},sync::OnceLock};
use crate::{Config,Context,config,verify_withdrawal,wire};
static CONFIG:OnceLock<Result<Config,String>>=OnceLock::new();

/// Explicit startup init; entropy/constructor failure aborts startup.
#[unsafe(no_mangle)]
pub extern "C" fn zk9_pq_withdraw32_init()->i32 {
    match catch_unwind(||CONFIG.get_or_init(config)) {Ok(Ok(_))=>0,_=>-1}
}
/// 0=valid; 1=invalid framing/statement/proof; -1=verifier not initialized.
/// Context and expected fee must originate from authenticated pool configuration.
/// This verifies a relation only, NOT root freshness, spentness or registration
/// of the protected account. Those belong to the keeper's atomic transition.
/// # Safety
/// Non-null pointers designate readable buffers of the stated lengths for the
/// whole call. No pointers are retained. The caller must not mutate the buffers
/// concurrently and must use the same verified envelope for the ledger update.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk9_pq_withdraw32_verify(context:*const u8,context_len:usize,
    expected_fee:u64,envelope:*const u8,envelope_len:usize)->i32 {
    if context.is_null() || envelope.is_null() || context_len!=96 || expected_fee==0
        || envelope_len<=wire::HEADER_BYTES+2*crate::PACKET_BYTES || envelope_len>wire::MAX_ENVELOPE_BYTES {return 1;}
    let Some(Ok(c))=CONFIG.get() else{return -1;};
    let result=catch_unwind(AssertUnwindSafe(|| {
        let ctx=unsafe{std::slice::from_raw_parts(context,context_len)};
        let bytes=unsafe{std::slice::from_raw_parts(envelope,envelope_len)};
        let expected=Context{network:ctx[..32].try_into().unwrap(),genesis:ctx[32..64].try_into().unwrap(),asset:ctx[64..96].try_into().unwrap(),fee:expected_fee};
        let d=wire::decode(&expected,bytes)?;
        verify_withdrawal(c,&d.statement,&d.proof)
    }));
    // Malformed proof panic is an invalid transaction; startup failure remains
    // a distinct result. Caller must never continue with an unavailable verifier.
    match result {Ok(Ok(()))=>0,Ok(Err(_))|Err(_)=>1}
}
