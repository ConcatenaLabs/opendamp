//! The contract-template whitelist with no node: the pinned template, the
//! address a policy recognises, the policy commitment, and the verifier on the
//! BitMachine.

use std::path::PathBuf;
use std::str::FromStr;

use opendamp::contracts::{
    guarded_order_program, guarded_order_witness, Contracts, GuardedOrderInstance, OrderPath, OrderTerms,
    GUARDED_ORDER, WHITELISTABLE,
};
use opendamp::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use opendamp::elements::{AssetId, OutPoint, Txid};
use opendamp::hexutil::{hex, unhex, unhex32};
use opendamp::net::Net;
use opendamp::programs::{self, render_verifier, render_verifier_with, AssetParams, SHAPES};
use opendamp::txbuild::{complete_transfer, p2tr_keypath_spk, Ctx, TransferReq};

fn read(name: &str) -> serde_json::Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn key(byte: u8) -> ([u8; 32], XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap());
    ([byte; 32], kp.x_only_public_key().0)
}

fn params() -> AssetParams {
    AssetParams {
        asset_a: AssetId::from_slice(&[0xaa; 32]).unwrap(),
        asset_v: AssetId::from_slice(&[0xbb; 32]).unwrap(),
        q: 100_000,
    }
}

fn listed() -> Contracts {
    Contracts::from_hashes(&[GUARDED_ORDER.template_hash]).unwrap()
}

#[test]
fn the_pinned_template_is_the_vendored_descriptor() {
    let d = read("contracts/seqdex_guarded_order.descriptor.json");
    assert_eq!(d["template"]["name"], GUARDED_ORDER.name);
    assert_eq!(d["template_hash"].as_str().unwrap(), hex(&GUARDED_ORDER.template_hash));
    let leaf = &d["template"]["tree"]["branch"][0]["simplicity"];
    assert_eq!(leaf["cmr"].as_str().unwrap(), hex(&GUARDED_ORDER.cmr));
    assert_eq!(leaf["compiler"]["version"], "0.7.2");
    // The data leaf's terms, in the order the verifier's recogniser hashes them.
    let data: Vec<&str> = d["template"]["tree"]["branch"][1]["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        data,
        [
            "ASSET_A", "ASSET_B", "RATE_NUM", "RATE_DEN", "MIN_LOT", "MAKER", "EXPIRY", "REFUND_KEY",
            "GUARD_ASSET", "GUARD_AMOUNT"
        ]
    );
    let f = read("contracts/seqdex_guarded_order.fills.json");
    assert_eq!(f["template_hash"], d["template_hash"]);
    assert_eq!(f["cmr"], leaf["cmr"]);
    assert_eq!(WHITELISTABLE, &[&GUARDED_ORDER]);
}

/// Every vector of the template derives, in this crate, to the same data
/// leaf, script, address and control block as the template's own readers.
#[test]
fn the_order_address_matches_the_template_vectors() {
    let v = read("contracts/seqdex_guarded_order.vectors.json");
    for a in v["addresses"].as_array().unwrap() {
        let p = &a["params"];
        let h = |k: &str| unhex32(p[k].as_str().unwrap()).unwrap();
        let n = |k: &str| u64::from_str_radix(p[k].as_str().unwrap(), 16).unwrap();
        let mut asset_b = h("ASSET_B");
        asset_b.reverse(); // internal order in the params, display order in an AssetId
        let inst = GuardedOrderInstance {
            asset_a: h("ASSET_A"),
            terms: OrderTerms {
                asset_b: AssetId::from_str(&hex(&asset_b)).unwrap(),
                rate_num: n("RATE_NUM"),
                rate_den: n("RATE_DEN"),
                min_lot: n("MIN_LOT"),
                maker: h("MAKER"),
                expiry: n("EXPIRY") as u32,
            },
            refund_key: h("REFUND_KEY"),
            guard_asset: h("GUARD_ASSET"),
            guard_amount: n("GUARD_AMOUNT"),
        };
        let name = a["name"].as_str().unwrap();
        assert_eq!(hex(&inst.data()), a["leaves"]["terms"]["data"].as_str().unwrap(), "{name}");
        let (info, cb) = inst.spend_info();
        assert_eq!(hex(info.script_pubkey.as_bytes()), a["script_pubkey"].as_str().unwrap(), "{name}");
        assert_eq!(hex(&cb.serialize()), a["leaves"]["order"]["control_block"].as_str().unwrap(), "{name}");
        let regtest = &opendamp::net::ELEMENTS_REGTEST_ADDRESS_PARAMS;
        assert_eq!(info.address(regtest).to_string(), a["address"]["elementsregtest"].as_str().unwrap(), "{name}");
    }
}

/// A spend's witness is the data leaf's bytes, PATH and, for the refund, the
/// signature: `0x40` and `0x00` close a fill's.
#[test]
fn the_order_witness_is_the_terms_and_the_path() {
    let (_, alice) = key(1);
    let terms = OrderTerms {
        asset_b: AssetId::from_slice(&[0xcc; 32]).unwrap(),
        rate_num: 3,
        rate_den: 2,
        min_lot: 1_000,
        maker: [0x11; 32],
        expiry: 1_200,
    };
    let inst = GuardedOrderInstance::for_policy(&params(), terms, &alice);
    let mut want = inst.data();
    want.push(0x40);
    assert_eq!(guarded_order_witness(&inst, OrderPath::Partial, None), want);
    *want.last_mut().unwrap() = 0x00;
    assert_eq!(guarded_order_witness(&inst, OrderPath::Whole, None), want);
    // Refund: a 1 bit, then the 64 signature bytes shifted by one bit.
    let sig = [0xffu8; 64];
    let w = guarded_order_witness(&inst, OrderPath::Refund, Some(&sig));
    assert_eq!(w.len(), 196 + 65);
    assert_eq!(&w[..196], &inst.data()[..]);
    assert_eq!(w[196], 0xff);
    assert_eq!(w[196 + 64], 0x80);
    // The programs are the template's four constants.
    let f = read("contracts/seqdex_guarded_order.fills.json");
    for (path, expiry, k) in [
        (OrderPath::Partial, 1_200, "fill"),
        (OrderPath::Whole, 1_200, "fill_whole"),
        (OrderPath::Refund, 1_200, "refund_height"),
        (OrderPath::Refund, 600_000_000, "refund_time"),
    ] {
        assert_eq!(
            hex(&guarded_order_program(path, expiry).unwrap()),
            f["paths"][k]["program"].as_str().unwrap()
        );
    }
    // The policy fixes the guard: the asset's verifier asset and q.
    assert_eq!(inst.guard_asset, programs::asset_internal_bytes(&params().asset_v));
    assert_eq!(inst.guard_amount, params().q);
    assert_eq!(inst.asset_a, programs::asset_internal_bytes(&params().asset_a));
    assert_eq!(inst.refund_key, alice.serialize());
}

#[test]
fn a_list_has_one_encoding_and_names_only_what_the_verifier_can_recognise() {
    assert!(Contracts::none().is_empty());
    assert_eq!(Contracts::none().commitment(), [0u8; 32]);
    let e = Contracts::from_hashes(&[[0x42; 32]]).unwrap_err();
    assert!(e.contains("is not one this build can whitelist"), "{e}");
    let e = Contracts::from_hashes(&[GUARDED_ORDER.template_hash, GUARDED_ORDER.template_hash]).unwrap_err();
    assert!(e.contains("listed twice"), "{e}");
    let c = listed();
    assert_ne!(c.commitment(), [0u8; 32]);
    assert_eq!(
        hex(&c.commitment()),
        read("vectors/contracts.json")["policy"]["contracts_commitment"].as_str().unwrap()
    );
}

/// A policy that lists nothing renders and commits exactly as before, and
/// listing the template changes pi, every verifier leaf and the address.
#[test]
fn listing_moves_the_policy_and_not_listing_moves_nothing() {
    for shape in SHAPES {
        assert_eq!(render_verifier_with(shape, &Contracts::none()), render_verifier(shape));
        let src = render_verifier_with(shape, &listed());
        assert!(src.contains("check_input_c(") && src.contains("check_output_c("));
        assert!(!src.contains("%%"));
    }
    let net = Net::testnet();
    let (_, alice) = key(1);
    let wl = vec![opendamp::dmt::Entry::unrestricted(alice.serialize())];
    let plain = Ctx::with_policy(net, params(), alice, wl.clone(), &[], programs::NO_LIMIT, 0).unwrap();
    let none =
        Ctx::with_policy_and_contracts(net, params(), alice, wl.clone(), &[], programs::NO_LIMIT, 0, Contracts::none())
            .unwrap();
    assert_eq!(plain.pi, none.pi);
    assert_eq!(plain.cv_info().script_pubkey, none.cv_info().script_pubkey);
    let with = Ctx::with_policy_and_contracts(net, params(), alice, wl, &[], programs::NO_LIMIT, 0, listed()).unwrap();
    assert_ne!(plain.pi, with.pi);
    assert_ne!(plain.cv_info().script_pubkey, with.cv_info().script_pubkey);
    for shape in SHAPES {
        assert_ne!(plain.p_cmr(shape).unwrap(), with.p_cmr(shape).unwrap(), "{shape}");
    }
    // U is the asset's for life: listing a contract does not touch it.
    assert_eq!(plain.u_cmr(), with.u_cmr());
}

/// The vectors of the example policy that lists the order match what this
/// build derives, so an independent implementation can pin them.
#[test]
fn the_contracts_vectors_are_current() {
    let v = read("vectors/contracts.json");
    let snap = read("examples/snapshot-contracts.json");
    assert_eq!(v["policy"]["pi"], snap["pi"]);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_opendamp"))
        .args(["derive", "--snapshot"])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/snapshot-contracts.json"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    for shape in v["programs"]["verifier_shapes"].as_array().unwrap() {
        let line = format!("P   CMR {:>5}  {}", shape["shape"].as_str().unwrap(), shape["cmr"].as_str().unwrap());
        assert!(text.contains(&line), "{line} not in\n{text}");
    }
}

/// An ordinary transfer under a policy that lists contracts runs on the
/// BitMachine: the wider slot witness carries a plain payment.
#[test]
fn an_ordinary_transfer_still_settles_under_a_listing_policy() {
    let (alice_sk, alice) = key(1);
    let (_, bob) = key(2);
    let (fee_sk, fee_key) = key(3);
    let wl = vec![
        opendamp::dmt::Entry::unrestricted(alice.serialize()),
        opendamp::dmt::Entry::unrestricted(bob.serialize()),
    ];
    let ctx = Ctx::with_policy_and_contracts(Net::testnet(), params(), alice, wl, &[], programs::NO_LIMIT, 0, listed())
        .unwrap();
    let op = |b: u8| OutPoint::new(Txid::from_str(&hex(&[b; 32])).unwrap(), 0);
    let req = TransferReq {
        sender: alice,
        sender_utxos: vec![(op(1), 5_000)],
        recipient: bob,
        amount: 2_000,
        verifier_outpoint: op(2),
        fee_utxo: (op(3), AssetId::from_slice(&[0xdd; 32]).unwrap(), 10_000),
        fee_key,
        fee_amount: 1_000,
        fee_change_spk: p2tr_keypath_spk(&fee_key),
        locktime: 0,
        recipient_spk_override: None,
    };
    let (_tx, report) = complete_transfer(&ctx, &req, &alice_sk, &fee_sk, true).expect("U and P run");
    assert!(report.verifier_weight() < report.verifier_budget());
    let _ = unhex("00");
}
