//! Exact serialized component sizes; these are not additive across nesting.
use crate::PaymentProof;
pub fn sizes(p:&PaymentProof)->serde_json::Value {
    macro_rules! size {($x:expr)=>{postcard::to_allocvec(&$x).expect("serializable proof").len()};}
    let fri=&p.opening_proof.1;
    let input=fri.input_openings.iter().map(|b|serde_json::json!({
        "bytes":size!(b),"row_values_bytes":size!(b.opened_values),
        "authentication_bytes":size!(b.opening_proof),
        "queries":b.opened_values.len(),
        "matrix_widths_first_query":b.opened_values.first().map(|q|q.iter().map(Vec::len).collect::<Vec<_>>())
    })).collect::<Vec<_>>();
    serde_json::json!({"total":size!(p),"commitments":size!(p.commitments),
        "opened_values":size!(p.opened_values),"opening_proof":size!(p.opening_proof),
        "trace_local":size!(p.opened_values.trace_local),"trace_next":size!(p.opened_values.trace_next),
        "mask_openings":size!(p.opening_proof.0),"fri_input_batches":input,
        "fri_commit_phase_openings":size!(fri.commit_phase_openings),
        "fri_commitments":size!(fri.commit_phase_commits),"fri_final_poly":size!(fri.final_poly)})
}
