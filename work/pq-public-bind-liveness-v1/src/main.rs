use p3_air::symbolic::{AirLayout,get_symbolic_constraints};
use serde_json::json;
use zk9_public_bind_liveness_lab::{air::PaymentAir,DeliveryAir,Val};
fn main() {
    assert_eq!(std::env::args().skip(1).collect::<Vec<_>>(),vec!["profile"]);
    let old=zk9_private_send_lab::DeliveryAir(zk9_private_send_lab::air::PaymentAir::new());
    let new=DeliveryAir(PaymentAir::new());
    assert_eq!(old.0.graph.height(),new.0.graph.height());
    assert_eq!(old.0.graph.blocks.len(),new.0.graph.blocks.len());
    let a=get_symbolic_constraints::<Val,_>(&old,AirLayout::from_air::<Val>(&old));
    let b=get_symbolic_constraints::<Val,_>(&new,AirLayout::from_air::<Val>(&new));
    let degree=|v:&Vec<p3_air::symbolic::SymbolicExpression<Val>>|v.iter().map(|x|x.degree_multiple()).max().unwrap();
    let report=json!({
        "status":"MEASURED_AIR_SHAPE_ONLY",
        "baseline":{"width":old.0.width(),"registers":old.0.layout.columns,"constraints":a.len(),"max_degree":degree(&a)},
        "candidate":{"width":new.0.width(),"registers":new.0.layout.columns,"constraints":b.len(),"max_degree":degree(&b)},
        "height":new.0.graph.height(),"blocks":new.0.graph.blocks.len(),
        "bindings":new.0.bindings.iter().map(|x|json!({"name":x.name,"block":x.block,"public_offset":x.public_offset,"second_input":x.second_input})).collect::<Vec<_>>(),
        "proof_generated":false,"equivalent_security_proven":false,"production_ready":false
    });
    println!("{}",serde_json::to_string_pretty(&report).unwrap());
}
