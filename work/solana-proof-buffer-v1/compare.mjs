// Compare two independent local runs; never infer proof verification from transport.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const get=async p=>JSON.parse(await readFile(new URL(p,import.meta.url),'utf8'));
const a=await get('./evidence/final-01.json'),b=await get('./evidence/final-02.json');
for(const r of [a,b]){
 assert.equal(r.status,'PASS_TRANSPORT_ONLY');assert.equal(r.checks.length,17);
 assert.equal(new Set(r.checks).size,17);
 for(const flag of ['proof_verified_on_solana','bridge_implemented','private_transfers_implemented','public_network'])assert.equal(r[flag],false);
 assert.ok(r.max_transaction_bytes<=1232);assert.ok(r.upload_wall_seconds>0);
 assert.equal(r.chunk_count,Math.ceil(r.payload_bytes/r.chunk_bytes));
 assert.equal(r.account_bytes,85+Math.ceil(r.chunk_count/8)+32*r.chunk_count+r.payload_bytes);
 assert.equal(r.submitted_transactions,r.chunk_count+7);
 assert.equal(r.actual_fee_lamports,(r.submitted_transactions+2)*5000);
 assert.ok(r.compute_samples.every(x=>Number.isSafeInteger(x.compute_units)&&x.compute_units>0));
}
for(const field of ['checks','version','fixture_sha256','payload_bytes','chunk_bytes','chunk_count','account_bytes','refundable_account_deposit_lamports','submitted_transactions','max_transaction_bytes','actual_fee_lamports','compute_samples','program_sha256'])assert.deepEqual(a[field],b[field],field);
const elf=await readFile(new URL('./bin/zk9_solana_proof_buffer_lab.so',import.meta.url));
assert.equal(createHash('sha256').update(elf).digest('hex'),a.program_sha256);
assert.equal(b.validator_forced_kill,false);assert.ok(b.validator_exit_code===0||b.validator_exit_signal==='SIGINT');
console.log(JSON.stringify({status:'PASS',independent_runs:2,functional_checks_per_run:a.checks.length,upload_seconds:[a.upload_wall_seconds,b.upload_wall_seconds],proof_verification:false},null,2));
