use super::*;

fn statement(fee: u64) -> Statement {
    Statement { fee, network: [1; 32], genesis: [2; 32], asset: [3; 32] }
}
fn copy(proof: &BalanceProof) -> BalanceProof {
    postcard::from_bytes(&postcard::to_allocvec(proof).unwrap()).unwrap()
}

#[test]
fn integer_boundary_fixtures_satisfy_air() {
    for (i, o, f) in [
        ([0, 0], [0, 0], 0),
        ([u64::MAX, u64::MAX], [u64::MAX, u64::MAX], 0),
        ([u64::MAX, u64::MAX], [u64::MAX, 0], u64::MAX),
        ([65536, 0], [65535, 0], 1),
        ([65535, 65535], [65536, 65534], 0),
        ([1000000, 500000], [900000, 599999], 1),
    ] {
        p3_air::check_constraints(&BalanceAir, &trace(i, o, f).unwrap(), &statement(f).public_values());
    }
}

#[test]
fn prover_rejects_inflation_and_u64_wraparound() {
    assert!(trace([1, 0], [2, 0], 0).is_err());
    assert!(trace([u64::MAX, 1], [0, 0], 0).is_err());
    assert!(trace([0, 0], [u64::MAX, 1], 0).is_err());
    assert!(trace([1, 0], [1, 0], 1).is_err());
}

#[test]
fn independent_verifier_rejects_mutations_and_rebinding() {
    let prover = config().unwrap();
    let verifier = config().unwrap();
    let s = statement(1);
    let p = prove_balance(&prover, [1000000, 500000], [900000, 599999], &s).unwrap();
    verify_balance(&verifier, &p, &s).unwrap();
    let bytes = postcard::to_allocvec(&p).unwrap();
    let roundtrip = postcard::from_bytes(&bytes).unwrap();
    verify_balance(&verifier, &roundtrip, &s).unwrap();
    assert!(postcard::from_bytes::<BalanceProof>(&bytes[..bytes.len() / 2]).is_err());
    for k in 0..4 {
        let mut altered = s.clone();
        match k { 0 => altered.fee += 1, 1 => altered.network[0] ^= 1,
            2 => altered.genesis[31] ^= 1, _ => altered.asset[15] ^= 1 }
        assert!(verify_balance(&verifier, &p, &altered).is_err(), "context mutation {k}");
    }
    for k in 0..7 {
        let mut bad = copy(&p);
        match k {
            0 => bad.commitments.trace = bad.commitments.quotient_chunks.clone(),
            1 => bad.commitments.quotient_chunks = bad.commitments.trace.clone(),
            2 => bad.commitments.random = None,
            3 => bad.commitments.random = Some(bad.commitments.trace.clone()),
            4 => bad.opened_values.random = None,
            5 => bad.opened_values.trace_local[0] += Challenge::ONE,
            _ => bad.degree_bits += 1,
        }
        assert!(verify_balance(&verifier, &bad, &s).is_err(), "proof mutation {k}");
    }
    // Same witness, new masks on the same config and on an independent config.
    for cfg in [&prover, &verifier] {
        let fresh = prove_balance(cfg, [1000000, 500000], [900000, 599999], &s).unwrap();
        verify_balance(&verifier, &fresh, &s).unwrap();
        assert_ne!(bytes, postcard::to_allocvec(&fresh).unwrap());
        assert_ne!(postcard::to_allocvec(&p.commitments.trace).unwrap(), postcard::to_allocvec(&fresh.commitments.trace).unwrap());
    }
}

#[test]
fn malicious_traces_fail_at_verifier_without_host_balance_check() {
    // Release mode: bypass trace validation and call the real prover directly.
    // An honest host's u128 check is NOT the security boundary.
    let cfg = config().unwrap();
    let s = statement(1);
    let honest = trace([65536, 0], [65535, 0], 1).unwrap();
    for kind in 0..4 {
        let mut bad = honest.clone();
        for row in bad.values.chunks_exact_mut(WIDTH) {
            match kind {
                0 => row[128] = Val::ZERO, // breaks exact conservation
                1 => row[0] = Val::from_u8(2), // non-boolean amount bit
                2 => row[320] = Val::from_u8(2), // non-boolean carry
                _ => row[0] += Val::ONE, // integer imbalance of one
            }
        }
        match prove(&cfg, &BalanceAir, bad, &s.public_values()) {
            Ok(p) => assert!(verify_balance(&cfg, &p, &s).is_err(), "malicious trace {kind}"),
            Err(_) => (),
        }
    }
}

#[test]
fn insufficient_masking_budget_fails_closed() {
    let cfg = config().unwrap();
    let s = statement(1);
    let t = trace([65536, 0], [65535, 0], 1).unwrap();
    let too_small = RowMajorMatrix::new(t.values[..WIDTH * 64].to_vec(), WIDTH);
    assert!(prove(&cfg, &BalanceAir, too_small, &s.public_values()).is_err());
}
