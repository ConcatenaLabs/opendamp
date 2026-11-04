//! The transaction encoding is Sequentia's: an asset issuance carries one
//! extra byte, the asset's denomination (decimal places), after the inflation
//! keys. Stock rust-elements has no such byte, so a Sequentia issuance would not
//! parse with it. These tests fail unless the crate is built against the
//! Sequentia build of `elements` (the `[patch.crates-io]` in Cargo.toml).
//!
//! The regtest suite (`tests/regtest.rs`, proof 0) parses an issuance the node
//! itself made; this test needs no node.

use opendamp::elements::confidential;
use opendamp::elements::hashes::Hash as _;
use opendamp::elements::encode::{deserialize, serialize};
use opendamp::elements::{AssetIssuance, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness};

fn issuance_tx(denomination: u8) -> Transaction {
    let issuance = AssetIssuance {
        asset_blinding_nonce: opendamp::elements::secp256k1_zkp::ZERO_TWEAK,
        asset_entropy: [7; 32],
        amount: confidential::Value::Explicit(123_456),
        inflation_keys: confidential::Value::Explicit(1),
        denomination,
    };
    Transaction {
        version: 2,
        lock_time: opendamp::elements::LockTime::ZERO,
        input: vec![TxIn {
            // Not the null (coinbase) outpoint, whose index carries no issuance flag.
            previous_output: OutPoint::new(opendamp::elements::Txid::all_zeros(), 1),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: issuance,
            witness: TxInWitness::default(),
        }],
        output: vec![],
    }
}

#[test]
fn issuance_denomination_round_trips() {
    for d in [0u8, 2, 8] {
        let tx = issuance_tx(d);
        let bytes = serialize(&tx);
        let back: Transaction = deserialize(&bytes).expect("a Sequentia issuance parses");
        assert_eq!(back.input[0].asset_issuance.denomination, d);
        assert_eq!(serialize(&back), bytes, "re-serialises byte for byte");
    }
}

#[test]
fn issuance_carries_the_denomination_byte() {
    // Two issuances differing only in denomination differ in exactly one byte,
    // the one after the inflation keys; the null default is 8.
    let a = serialize(&issuance_tx(2));
    let b = serialize(&issuance_tx(8));
    assert_eq!(a.len(), b.len());
    let diffs: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    assert_eq!(diffs.len(), 1, "only the denomination byte differs");
    assert_eq!((a[diffs[0]], b[diffs[0]]), (2, 8));
    assert_eq!(AssetIssuance::null().denomination, 8);
}

#[test]
fn stock_layout_does_not_parse_as_sequentia() {
    // The same issuance with the denomination byte removed, as stock Elements
    // would write it, is not a Sequentia transaction.
    let mut bytes = serialize(&issuance_tx(2));
    let at = (0..bytes.len())
        .find(|&i| bytes[i] == 2 && serialize(&issuance_tx(3))[i] == 3)
        .expect("denomination byte");
    bytes.remove(at);
    assert!(deserialize::<Transaction>(&bytes).is_err());
}
