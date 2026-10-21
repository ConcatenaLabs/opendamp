//! The contract-template whitelist against a real Sequentia node.
//!
//! Ignored by default (it spawns a node). Run with:
//!
//!     cargo test --test regtest_contracts -- --ignored --nocapture
//!
//! Binary discovery is `tests/regtest.rs`'s: $OPENDAMP_NODE_BIN, else
//! ../Sequentia/src/sequentiad beside this checkout. The node runs on
//! `elementsregtest` with Simplicity active from genesis and `-par=1`, so a block
//! refused for a script names the script's error.
//!
//! A network-enforced asset A, under a policy that lists SeqDEX's guarded order
//! (`seqdex/guarded-order`), enters an order, is filled by a whitelisted holder,
//! and leaves it:
//!
//!   E  alice moves A from her user covenant into her own guarded order;
//!   F  anyone fills it in part, the A going to bob, a whitelisted holder: the
//!      verifier proves alice (the order's owner) as the sender, with no
//!      signature of hers in the transaction;
//!   R  after the expiry alice takes the rest back into her user covenant;
//!   W  a second order is filled whole;
//!   I  the issuer key alone, at input 0, fills an order and sends the A
//!      anywhere: the power the design states plainly.
//!
//! Every refusal is a transaction forced into a block with `generateblock`,
//! beside an accepted control that differs only in the property under test. A
//! verifier witness signs nothing, so a negative carries its control's pruned
//! verifier program and witness unchanged (and the order's, which is a constant);
//! only the inputs that sign are re-signed for the negative transaction.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use opendamp::contracts::{GuardedOrderInstance, OrderPath, OrderTerms, GUARDED_ORDER};
use opendamp::elements::confidential;
use opendamp::elements::hashes::{sha256, Hash};
use opendamp::elements::pset::serialize::Serialize;
use opendamp::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use opendamp::elements::{
    AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness, TxOut, Txid,
};
use opendamp::hexutil::hex;
use opendamp::net::Net;
use opendamp::programs::{self, AssetParams, Contracts};
use opendamp::txbuild::{
    attach_order_spend, attach_policy_verifier, attach_simplicity, covenant_env, p2tr_keypath_spk, sig_all_digest,
    sign_bip340, sign_fee_input, sign_user_input, AInput, AOutput, Ctx, PolicySpend,
};

// ---------------------------------------------------------------- node driver

struct Node {
    child: Child,
    cli: PathBuf,
    datadir: PathBuf,
    rpcport: u16,
}

impl Node {
    fn locate_binaries() -> Option<(PathBuf, PathBuf)> {
        let daemon = match std::env::var("OPENDAMP_NODE_BIN") {
            Ok(p) => PathBuf::from(p),
            Err(_) => Path::new(env!("CARGO_MANIFEST_DIR")).join("../Sequentia/src/sequentiad"),
        };
        let cli = daemon.parent()?.join("sequentia-cli");
        (daemon.is_file() && cli.is_file()).then_some((daemon, cli))
    }

    fn start() -> Option<Node> {
        let (daemon, cli) = Self::locate_binaries()?;
        let rpcport = 24000 + (std::process::id() % 2000) as u16;
        let datadir = std::env::temp_dir().join(format!("opendamp-contracts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).expect("datadir");
        let child = Command::new(&daemon)
            .args([
                "-chain=elementsregtest",
                &format!("-datadir={}", datadir.display()),
                "-server=1",
                "-listen=0",
                "-rpcuser=od",
                "-rpcpassword=od",
                &format!("-rpcport={rpcport}"),
                &format!("-port={}", rpcport + 2000),
                "-evbparams=simplicity:-1:::",
                "-anyonecanspendaremine=1",
                "-initialfreecoins=2100000000000000",
                "-validatepegin=0",
                "-con_default_blinded_addresses=0",
                "-con_any_asset_fees=1",
                "-txindex=1",
                "-par=1",
                "-fallbackfee=0.0001",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let node = Node { child, cli, datadir, rpcport };
        let deadline = Instant::now() + Duration::from_secs(60);
        while node.try_cli(&["getblockchaininfo"]).is_err() {
            assert!(Instant::now() < deadline, "node RPC did not come up");
            std::thread::sleep(Duration::from_millis(250));
        }
        Some(node)
    }

    fn try_cli(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.cli)
            .args([
                "-chain=elementsregtest".to_string(),
                format!("-datadir={}", self.datadir.display()),
                "-rpcuser=od".to_string(),
                "-rpcpassword=od".to_string(),
                format!("-rpcport={}", self.rpcport),
            ])
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    fn cli(&self, args: &[&str]) -> String {
        self.try_cli(args).unwrap_or_else(|e| panic!("cli {args:?} failed: {e}"))
    }

    fn cli_json(&self, args: &[&str]) -> serde_json::Value {
        let s = self.cli(args);
        serde_json::from_str(&s).unwrap_or_else(|e| panic!("cli {args:?} bad json: {e}: {s}"))
    }

    fn height(&self) -> u32 {
        self.cli(&["getblockcount"]).parse().unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.try_cli(&["stop"]);
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                _ if Instant::now() > deadline => {
                    let _ = self.child.kill();
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

// ---------------------------------------------------------------- helpers

fn key(byte: u8) -> ([u8; 32], XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let sk = [byte; 32];
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk).unwrap());
    (sk, kp.x_only_public_key().0)
}

fn tx_hex(tx: &Transaction) -> String {
    hex(&tx.serialize())
}

fn txin(op: OutPoint) -> TxIn {
    TxIn {
        previous_output: op,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::from_consensus(0xffff_fffe),
        asset_issuance: Default::default(),
        witness: TxInWitness::default(),
    }
}

fn out(asset: AssetId, value: u64, spk: &Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey: spk.clone(),
        witness: Default::default(),
    }
}

#[derive(Clone, Debug)]
struct Coin {
    op: OutPoint,
    txout: TxOut,
}

impl Coin {
    fn value(&self) -> u64 {
        self.txout.value.explicit().unwrap()
    }
}

/// The output of `txid` paying `spk`, as a coin.
fn coin(node: &Node, txid: &str, spk: &Script) -> Coin {
    let raw = node.cli(&["getrawtransaction", txid]);
    let tx: Transaction = opendamp::elements::encode::deserialize(&opendamp::hexutil::unhex(&raw).unwrap()).unwrap();
    let (n, o) = tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey == *spk)
        .unwrap_or_else(|| panic!("no output paying {} in {txid}", hex(spk.as_bytes())));
    Coin { op: OutPoint::new(Txid::from_str(txid).unwrap(), n as u32), txout: o.clone() }
}

fn coin_at(node: &Node, txid: &str, n: u32) -> Coin {
    let raw = node.cli(&["getrawtransaction", txid]);
    let tx: Transaction = opendamp::elements::encode::deserialize(&opendamp::hexutil::unhex(&raw).unwrap()).unwrap();
    Coin { op: OutPoint::new(Txid::from_str(txid).unwrap(), n), txout: tx.output[n as usize].clone() }
}

/// Every proof's outcome, printed as it happens and written at the end.
struct Record {
    rows: Vec<serde_json::Value>,
    path: Option<PathBuf>,
}

impl Record {
    fn push(&mut self, v: serde_json::Value) {
        println!("{v}");
        self.rows.push(v);
        if let Some(p) = &self.path {
            std::fs::write(p, serde_json::to_string_pretty(&self.rows).unwrap()).unwrap();
        }
    }
}

/// Mine `tx` through the mempool; returns its txid and the node's vsize.
fn mine(node: &Node, rec: &mut Record, label: &str, tx: &Transaction, extra: serde_json::Value) -> String {
    let accept = node.cli_json(&["testmempoolaccept", &format!("[\"{}\"]", tx_hex(tx))]);
    assert_eq!(accept[0]["allowed"].as_bool(), Some(true), "{label}: {accept}");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(tx)]);
    let addr = node.cli(&["getnewaddress"]);
    node.cli(&["generatetoaddress", "1", &addr]);
    let v = node.cli_json(&["getrawtransaction", &txid, "1"]);
    assert!(v["confirmations"].as_u64().unwrap_or(0) >= 1, "{label} not confirmed");
    rec.push(serde_json::json!({
        "proof": label, "mined": true, "txid": txid, "vsize": v["vsize"], "weight": v["weight"], "detail": extra,
    }));
    txid
}

/// Which Simplicity inputs of `tx` fail, each program decoded from its witness
/// stack and run on the BitMachine against `tx`, as consensus runs it. The
/// node's block error names the failure but not the input; this names the
/// input.
fn failing_inputs(net: &Net, tx: &Transaction, prev: &[TxOut]) -> Vec<(usize, String)> {
    use opendamp::elements::taproot::ControlBlock;
    use opendamp::simplicityhl::simplicity::jet::Elements;
    use opendamp::simplicityhl::simplicity::{BitIter, BitMachine, Cmr, RedeemNode};
    let mut out = Vec::new();
    for (i, input) in tx.input.iter().enumerate() {
        let st = &input.witness.script_witness;
        if st.len() != 4 {
            continue; // a key-path spend
        }
        let cb = ControlBlock::from_slice(&st[3]).expect("control block");
        let cmr = Cmr::from_byte_array(st[2].clone().try_into().expect("32-byte root"));
        let node = match RedeemNode::<Elements>::decode(BitIter::from(st[1].as_slice()), BitIter::from(st[0].as_slice())) {
            Ok(n) => n,
            Err(e) => {
                out.push((i, format!("decode: {e}")));
                continue;
            }
        };
        assert_eq!(node.cmr(), cmr, "input {i}: the program is not the root it names");
        let env = covenant_env(net, tx, prev, i, cmr, cb);
        let mut mac = BitMachine::for_program(&node).expect("bit machine");
        if let Err(e) = mac.exec(&node, &env) {
            out.push((i, e.to_string()));
        }
    }
    out
}

/// The mempool accepts `control`, and refuses `tx`; a block forced with
/// `generateblock` refuses `tx` with an error naming `expect`, and the chain
/// does not move. Run locally, every Simplicity input of the control passes
/// and exactly the inputs `fails_at` of `tx` fail.
#[allow(clippy::too_many_arguments)]
fn refuse(
    node: &Node,
    rec: &mut Record,
    net: &Net,
    label: &str,
    (tx, prev): (&Transaction, &[TxOut]),
    (control, control_prev): (&Transaction, &[TxOut]),
    expect: &str,
    fails_at: &[usize],
) {
    assert_ne!(tx_hex(tx), tx_hex(control), "{label}: the control is the negative itself");
    let c_fail = failing_inputs(net, control, control_prev);
    assert!(c_fail.is_empty(), "{label}: the control fails locally: {c_fail:?}");
    let fail = failing_inputs(net, tx, prev);
    assert_eq!(
        fail.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        fails_at,
        "{label}: failing inputs {fail:?}"
    );
    let c = node.cli_json(&["testmempoolaccept", &format!("[\"{}\"]", tx_hex(control))]);
    assert_eq!(c[0]["allowed"].as_bool(), Some(true), "{label}: the control is refused: {c}");
    let m = node.cli_json(&["testmempoolaccept", &format!("[\"{}\"]", tx_hex(tx))]);
    assert_eq!(m[0]["allowed"].as_bool(), Some(false), "{label}: the mempool ACCEPTED it: {m}");
    let h0 = node.height();
    let addr = node.cli(&["getnewaddress"]);
    let block = node.try_cli(&["generateblock", &addr, &format!("[\"{}\"]", tx_hex(tx))]);
    let err = match block {
        Ok(b) => panic!("{label}: MINED by generateblock: {b}"),
        Err(e) => e,
    };
    assert_eq!(node.height(), h0, "{label}: the chain moved");
    assert!(err.contains(expect), "{label}: the block says {err:?}, expected {expect:?}");
    rec.push(serde_json::json!({
        "proof": label, "mined": false,
        "mempool": m[0]["reject-reason"], "block": err.lines().last().unwrap_or("").trim(),
        "control": c[0]["txid"],
        "failing_input_locally": fail.iter().map(|(i, e)| format!("input {i}: {e}")).collect::<Vec<_>>(),
    }));
}

/// The verifier witness of `control` on `tx`: the same pruned program, so what
/// the node runs is a well-formed verifier against `tx`.
fn splice_verifier(tx: &mut Transaction, control: &Transaction) {
    tx.input[0].witness = control.input[0].witness.clone();
}

fn spk_hash(s: &Script) -> [u8; 32] {
    sha256::Hash::hash(s.as_bytes()).to_byte_array()
}

/// SeqDEX's plain order (`seqdex/order`, not on any list) with the same terms:
/// its program beside the eight-term data leaf.
fn plain_order_spk(inst: &GuardedOrderInstance) -> Script {
    let plain_cmr =
        opendamp::hexutil::unhex32("f9b42b838b6295f4f376760fbb02eed9cb20f872f07ee4b9df7273d26822ee44").unwrap();
    let data = inst.data();
    opendamp::tapscript::leaf_beside_data(opendamp::simplicityhl::simplicity::Cmr::from_byte_array(plain_cmr), &data[..156])
        .0
        .script_pubkey
}

// -------------------------------------------------------------------- the test

#[test]
#[ignore = "spawns a Sequentia node; run with --ignored"]
fn a_network_enforced_asset_enters_an_order_and_leaves_it() {
    let Some(node) = Node::start() else {
        panic!("no node binary; set OPENDAMP_NODE_BIN");
    };
    let mut rec = Record { rows: Vec::new(), path: std::env::var("OPENDAMP_CONTRACTS_RECORD").ok().map(PathBuf::from) };
    node.cli(&["createwallet", "w"]);
    let mine_addr = node.cli(&["getnewaddress"]);
    node.cli(&["generatetoaddress", "101", &mine_addr]);
    node.cli(&["rescanblockchain"]);
    let dep = node.cli_json(&["getdeploymentinfo"]);
    assert_eq!(dep["deployments"]["simplicity"]["active"].as_bool(), Some(true), "simplicity must be active first");
    let version = node.cli_json(&["getnetworkinfo"])["subversion"].clone();
    let genesis = node.cli(&["getblockhash", "0"]);
    let net = Net::regtest(BlockHash::from_str(&genesis).unwrap());
    let policy_hex = node.cli_json(&["dumpassetlabels"])["bitcoin"].as_str().unwrap().to_string();
    let wallet_fee = format!("fee_asset_label={policy_hex}");
    let issue = |amount: &str| -> (String, AssetId) {
        let r = node.cli_json(&[
            "-named", "issueasset", &format!("assetamount={amount}"), "tokenamount=0", "blind=false",
            &format!("fee_asset={policy_hex}"),
        ]);
        let h = r["asset"].as_str().unwrap().to_string();
        let a = AssetId::from_str(&h).unwrap();
        (h, a)
    };
    let (a_hex, asset_a) = issue("1000");
    let (v_hex, asset_v) = issue("0.00100000");
    let (b_hex, asset_b) = issue("1000");
    let (f_hex, asset_fee) = issue("1000");
    let (w_hex, asset_w) = issue("0.00100000");
    node.cli(&["generatetoaddress", "1", &mine_addr]);
    // The fees of every hand-built transaction are paid in an issued asset.
    let mut rates = node.cli_json(&["getfeeexchangerates"]);
    rates[f_hex.as_str()] = serde_json::json!(100_000_000u64);
    node.cli(&["setfeeexchangerates", &rates.to_string()]);
    let q: u64 = 100_000;

    let (alice_sk, alice) = key(1);
    let (_bob_sk, bob) = key(2);
    let (fee_sk, fee_key) = key(3);
    let (_carol_sk, carol) = key(4);
    let (payer_sk, payer) = key(5);
    let (stranger_sk, stranger) = key(6);
    let (issuer_sk, issuer) = key(9);
    let params = AssetParams { asset_a, asset_v, q };
    let listed = Contracts::from_hashes(&[GUARDED_ORDER.template_hash]).unwrap();
    let wl = vec![opendamp::dmt::Entry::unrestricted(alice.serialize()), opendamp::dmt::Entry::unrestricted(bob.serialize())];
    let ctx = Ctx::with_policy_and_contracts(net, params, issuer, wl.clone(), &[], programs::NO_LIMIT, 0, listed.clone())
        .expect("the policy compiles");
    let unlisted = Ctx::with_policy(net, params, issuer, wl, &[], programs::NO_LIMIT, 0).unwrap();
    assert_ne!(ctx.pi, unlisted.pi, "pi commits to the contract list");
    assert_ne!(ctx.cv_info().script_pubkey, unlisted.cv_info().script_pubkey);
    rec.push(serde_json::json!({
        "node": version, "asset": a_hex, "verifier_asset": v_hex, "q": q,
        "contracts": [hex(&GUARDED_ORDER.template_hash)], "c_con": hex(&listed.commitment()),
        "pi": hex(&ctx.pi), "pi_without_the_list": hex(&unlisted.pi),
        "verifier_shapes": programs::SHAPES.iter().map(|s| serde_json::json!({
            "shape": s.name(), "cmr": ctx.p_cmr(*s).unwrap().to_string(),
        })).collect::<Vec<_>>(),
    }));

    // --- fund: A in alice's user covenant, q of V in the verifier, and the
    // plain coins (fees, a payer's B, a stranger's W) at key-path addresses.
    let addr_of = |spk: &Script| opendamp::elements::Address::from_script(spk, None, net.address_params).unwrap().to_string();
    let send = |spk: &Script, amount: &str, asset_hex: &str| -> String {
        node.cli(&[
            "-named", "sendtoaddress", &format!("address={}", addr_of(spk)), &format!("amount={amount}"),
            &format!("assetlabel={asset_hex}"), &wallet_fee,
        ])
    };
    let cu_alice = ctx.cu_info(&alice).script_pubkey;
    let cu_bob = ctx.cu_info(&bob).script_pubkey;
    let cu_carol = ctx.cu_info(&carol).script_pubkey;
    let cv = ctx.cv_info().script_pubkey.clone();
    let fee_spk = p2tr_keypath_spk(&fee_key);
    let payer_spk = p2tr_keypath_spk(&payer);
    let stranger_spk = p2tr_keypath_spk(&stranger);
    let t_a = send(&cu_alice, "5", &a_hex);
    let t_v = send(&cv, "0.00100000", &v_hex);
    // Mined in batches: the wallet chains its unconfirmed change, and the
    // mempool's ancestor limit stops a long chain.
    let t_fees: Vec<String> = (0..18).map(|_| send(&fee_spk, "1", &f_hex)).collect();
    node.cli(&["generatetoaddress", "1", &mine_addr]);
    let t_pay: Vec<String> = (0..8).map(|_| send(&payer_spk, "20", &b_hex)).collect();
    let t_w = send(&stranger_spk, "0.00100000", &w_hex);
    node.cli(&["generatetoaddress", "1", &mine_addr]);
    let alice_a = coin(&node, &t_a, &cu_alice);
    let mut verifier = coin(&node, &t_v, &cv);
    assert_eq!(verifier.value(), q);
    let mut fees: Vec<Coin> = t_fees.iter().map(|t| coin(&node, t, &fee_spk)).collect();
    let mut pays: Vec<Coin> = t_pay.iter().map(|t| coin(&node, t, &payer_spk)).collect();
    let w_coin = coin(&node, &t_w, &stranger_spk);
    const FEE: u64 = 60_000;

    // The order: A sold for B at 3 B per 2 A, alice's to take back from height
    // h+40, paying her plain key's script.
    let maker_spk = p2tr_keypath_spk(&alice);
    let terms = OrderTerms {
        asset_b,
        rate_num: 3,
        rate_den: 2,
        min_lot: 1_000,
        maker: spk_hash(&maker_spk),
        expiry: node.height() + 40,
    };
    let order = ctx.order(terms, &alice);
    let order_spk = order.script_pubkey();
    rec.push(serde_json::json!({
        "order": {"template": GUARDED_ORDER.name, "cmr": hex(&GUARDED_ORDER.cmr),
                  "address": order.spend_info().0.address(net.address_params).to_string(),
                  "data_leaf": hex(&order.data())},
    }));

    // ======================================================== E: entry
    // [V, C_U(alice), fee] -> [V', order(alice), C_U(alice) change, fee change, fee]
    let entry_tx = |out1: &Script, fee: &Coin| -> (Transaction, Vec<TxOut>) {
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![txin(verifier.op), txin(alice_a.op), txin(fee.op)],
            output: vec![
                out(asset_v, q, &cv),
                out(asset_a, 300_000_000, out1),
                out(asset_a, alice_a.value() - 300_000_000, &cu_alice),
                out(asset_fee, fee.value() - FEE, &fee_spk),
                TxOut::new_fee(FEE, asset_fee),
            ],
        };
        let prev = vec![verifier.txout.clone(), alice_a.txout.clone(), fee.txout.clone()];
        (tx, prev)
    };
    let sign_entry = |tx: &mut Transaction, prev: &[TxOut]| {
        sign_user_input(&ctx, tx, prev, 1, &alice_sk).expect("U signs");
        sign_fee_input(&net, tx, prev, 2, &fee_sk).unwrap();
    };
    let fee0 = fees.pop().unwrap();
    let (mut entry, prev) = entry_tx(&order_spk, &fee0);
    let into_own_order = PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::User)],
        outputs: vec![(1, AOutput::Order { owner: None, terms }), (2, AOutput::Change)],
    };
    let (vw, vc) = attach_policy_verifier(&ctx, &mut entry, &prev, &into_own_order, true).expect("the verifier accepts");
    sign_entry(&mut entry, &prev);

    // A control paying into an order bob owns: another owner, proven.
    let bob_order = ctx.order(terms, &bob);
    let (mut entry_bob, prev_b) = entry_tx(&bob_order.script_pubkey(), &fee0);
    let into_bobs_order = PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::User)],
        outputs: vec![(1, AOutput::Order { owner: Some(bob), terms }), (2, AOutput::Change)],
    };
    attach_policy_verifier(&ctx, &mut entry_bob, &prev_b, &into_bobs_order, true).expect("bob's order is recognised");
    sign_entry(&mut entry_bob, &prev_b);

    // Refusals at entry. Each negative carries the verifier witness of the
    // control beside it, pruned for the recognised order.
    const JET: &str = "mempool-script-verify-flag-failed (Assertion failed inside jet)";
    let negatives: Vec<(&str, Script, &Transaction)> = vec![
        ("entry/neg_into_a_template_not_on_the_list_seqdex_order", plain_order_spk(&order), &entry),
        ("entry/neg_listed_template_guarded_by_another_asset", {
            let mut i = order; i.guard_asset = opendamp::programs::asset_internal_bytes(&asset_w); i.script_pubkey()
        }, &entry),
        ("entry/neg_listed_template_guard_amount_q_plus_1", {
            let mut i = order; i.guard_amount = q + 1; i.script_pubkey()
        }, &entry),
        ("entry/neg_listed_template_selling_another_asset", {
            let mut i = order; i.asset_a = opendamp::programs::asset_internal_bytes(&asset_b); i.script_pubkey()
        }, &entry),
        ("entry/neg_listed_template_owned_by_a_key_not_on_the_whitelist", ctx.order(terms, &carol).script_pubkey(), &entry_bob),
    ];
    for (label, spk, control) in &negatives {
        let (mut bad, prev) = entry_tx(spk, &fee0);
        splice_verifier(&mut bad, control);
        sign_entry(&mut bad, &prev);
        refuse(&node, &mut rec, &net, label, (&bad, &prev), (control, &prev_b), JET, &[0]);
    }
    // And the builder names the refusal before any node sees it.
    let (mut bad, prev) = entry_tx(&ctx.order(terms, &carol).script_pubkey(), &fee0);
    let err = attach_policy_verifier(&ctx, &mut bad, &prev, &PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::User)],
        outputs: vec![(1, AOutput::Order { owner: Some(carol), terms }), (2, AOutput::Change)],
    }, true).unwrap_err();
    rec.push(serde_json::json!({"proof": "entry/builder_refuses_carols_order", "error": err}));

    let entry_id = mine(&node, &mut rec, "E/alice_moves_A_into_her_guarded_order", &entry, serde_json::json!({
        "verifier_stack_bytes": vw, "verifier_cost_milli_wu": vc, "verifier_budget_wu": vw * 4 + 50,
        "leaf": programs::shape_for(3, 5).unwrap().name(),
    }));
    verifier = coin_at(&node, &entry_id, 0);
    let o1 = coin_at(&node, &entry_id, 1);
    assert_eq!(o1.txout.script_pubkey, order_spk);
    let alice_change = coin_at(&node, &entry_id, 2);

    // ======================================================== F: fill
    // [V, order, payer's B, fee] -> [V', A to the taker, B to the maker (2),
    //  the rest (3), B change, fee change, fee]
    let fill_amount: u64 = 100_000_001;
    let price = (fill_amount as u128 * 3).div_ceil(2) as u64;
    let fill_tx = |taker_spk: &Script, v: &Coin, o: &Coin, pay: &Coin, fee: &Coin| -> (Transaction, Vec<TxOut>) {
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![txin(v.op), txin(o.op), txin(pay.op), txin(fee.op)],
            output: vec![
                out(asset_v, q, &cv),
                out(asset_a, fill_amount, taker_spk),
                out(asset_b, price, &maker_spk),
                out(asset_a, o.value() - fill_amount, &order_spk),
                out(asset_b, pay.value() - price, &payer_spk),
                out(asset_fee, fee.value() - FEE, &fee_spk),
                TxOut::new_fee(FEE, asset_fee),
            ],
        };
        let prev = vec![v.txout.clone(), o.txout.clone(), pay.txout.clone(), fee.txout.clone()];
        (tx, prev)
    };
    let fill_spend = PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::Order(terms))],
        outputs: vec![(1, AOutput::Pay(bob)), (3, AOutput::Order { owner: None, terms })],
    };
    let finish_fill = |tx: &mut Transaction, prev: &[TxOut], order_at: usize, pay_at: usize, fee_at: usize| {
        attach_order_spend(&net, tx, prev, order_at, &order, OrderPath::Partial, None).expect("the fill's stack");
        sign_fee_input(&net, tx, prev, pay_at, &payer_sk).unwrap();
        sign_fee_input(&net, tx, prev, fee_at, &fee_sk).unwrap();
    };
    let pay0 = pays.pop().unwrap();
    let fee1 = fees.pop().unwrap();
    let (mut fill, prev) = fill_tx(&cu_bob, &verifier, &o1, &pay0, &fee1);
    let (fw, fc) = attach_policy_verifier(&ctx, &mut fill, &prev, &fill_spend, true).expect("the verifier accepts the fill");
    finish_fill(&mut fill, &prev, 1, 2, 3);

    for (label, spk) in [
        ("fill/neg_pays_A_to_a_script_the_policy_refuses_a_plain_key", p2tr_keypath_spk(&bob)),
        ("fill/neg_pays_A_out_of_the_order_to_a_holder_not_on_the_whitelist", cu_carol.clone()),
        ("fill/neg_pays_A_into_a_template_not_on_the_list", plain_order_spk(&ctx.order(terms, &bob))),
    ] {
        let (mut bad, prev_bad) = fill_tx(&spk, &verifier, &o1, &pay0, &fee1);
        splice_verifier(&mut bad, &fill);
        finish_fill(&mut bad, &prev_bad, 1, 2, 3);
        refuse(&node, &mut rec, &net, label, (&bad, &prev_bad), (&fill, &prev), JET, &[0]);
    }
    // The order cannot be filled without the verifier: the payer's coin at
    // input 0 and nothing of V anywhere, the order at input 1 as before.
    {
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![txin(pay0.op), txin(o1.op), txin(fee1.op)],
            output: vec![
                out(asset_a, fill_amount, &p2tr_keypath_spk(&stranger)),
                out(asset_b, pay0.value() - price, &payer_spk),
                out(asset_b, price, &maker_spk),
                out(asset_a, o1.value() - fill_amount, &order_spk),
                out(asset_fee, fee1.value() - FEE, &fee_spk),
                TxOut::new_fee(FEE, asset_fee),
            ],
        };
        let prev_bad = vec![pay0.txout.clone(), o1.txout.clone(), fee1.txout.clone()];
        let mut bad = tx;
        finish_fill(&mut bad, &prev_bad, 1, 0, 2);
        refuse(&node, &mut rec, &net, "fill/neg_without_the_verifier_at_input_0", (&bad, &prev_bad), (&fill, &prev), JET, &[1]);
    }
    // ...nor beside another asset's q at input 0, which is what an order
    // guarded by that asset would accept.
    {
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![txin(w_coin.op), txin(o1.op), txin(pay0.op), txin(fee1.op)],
            output: vec![
                out(asset_w, q, &stranger_spk),
                out(asset_a, fill_amount, &p2tr_keypath_spk(&stranger)),
                out(asset_b, price, &maker_spk),
                out(asset_a, o1.value() - fill_amount, &order_spk),
                out(asset_b, pay0.value() - price, &payer_spk),
                out(asset_fee, fee1.value() - FEE, &fee_spk),
                TxOut::new_fee(FEE, asset_fee),
            ],
        };
        let prev_bad = vec![w_coin.txout.clone(), o1.txout.clone(), pay0.txout.clone(), fee1.txout.clone()];
        let mut bad = tx;
        sign_fee_input(&net, &mut bad, &prev_bad, 0, &stranger_sk).unwrap();
        finish_fill(&mut bad, &prev_bad, 1, 2, 3);
        refuse(&node, &mut rec, &net, "fill/neg_beside_q_of_another_asset_at_input_0", (&bad, &prev_bad), (&fill, &prev), JET, &[1]);
    }

    let order_stack: usize = fill.input[1].witness.script_witness.iter().map(Vec::len).sum();
    let fill_id = mine(&node, &mut rec, "F/the_order_filled_in_part_A_to_bob", &fill, serde_json::json!({
        "filled": fill_amount, "paid": price, "sender_proven": "alice (the order's owner), who signs nothing here",
        "verifier_stack_bytes": fw, "verifier_cost_milli_wu": fc, "verifier_budget_wu": fw * 4 + 50,
        "leaf": programs::shape_for(4, 7).unwrap().name(), "order_stack_bytes": order_stack,
    }));
    verifier = coin_at(&node, &fill_id, 0);
    let bob_a = coin_at(&node, &fill_id, 1);
    assert_eq!(bob_a.txout.script_pubkey, cu_bob);
    let o2 = coin_at(&node, &fill_id, 3);
    assert_eq!(o2.txout.script_pubkey, order_spk);

    // ======================================================== R: the refund
    let until = terms.expiry;
    while node.height() < until {
        node.cli(&["generatetoaddress", "1", &mine_addr]);
    }
    // [V, order, fee] -> [V', the rest to out1, fee change, fee], locked at the expiry.
    let refund_tx = |out1: &Script, fee: &Coin| -> (Transaction, Vec<TxOut>) {
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::from_consensus(until),
            input: vec![txin(verifier.op), txin(o2.op), txin(fee.op)],
            output: vec![
                out(asset_v, q, &cv),
                out(asset_a, o2.value(), out1),
                out(asset_fee, fee.value() - FEE, &fee_spk),
                TxOut::new_fee(FEE, asset_fee),
            ],
        };
        (tx, vec![verifier.txout.clone(), o2.txout.clone(), fee.txout.clone()])
    };
    let finish_refund = |tx: &mut Transaction, prev: &[TxOut]| {
        attach_order_spend(&net, tx, prev, 1, &order, OrderPath::Refund, Some(&alice_sk)).expect("the refund's stack");
        sign_fee_input(&net, tx, prev, 2, &fee_sk).unwrap();
    };
    let fee2 = fees.pop().unwrap();
    let (mut refund, prev) = refund_tx(&cu_alice, &fee2);
    let back_home = PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::Order(terms))],
        outputs: vec![(1, AOutput::Change)],
    };
    let (rw, rc) = attach_policy_verifier(&ctx, &mut refund, &prev, &back_home, true).expect("the refund passes");
    finish_refund(&mut refund, &prev);
    // A control of the same shape that pays bob, so a refusal of carol is the
    // proof's and not the change's.
    let (mut to_bob, prev_b) = refund_tx(&cu_bob, &fee2);
    attach_policy_verifier(&ctx, &mut to_bob, &prev_b, &PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::Order(terms))],
        outputs: vec![(1, AOutput::Pay(bob))],
    }, true).unwrap();
    finish_refund(&mut to_bob, &prev_b);
    for (label, spk) in [
        ("refund/neg_out_of_the_order_to_a_holder_not_on_the_whitelist", cu_carol.clone()),
        ("refund/neg_out_of_the_order_to_a_plain_key", p2tr_keypath_spk(&alice)),
    ] {
        let (mut bad, prev_bad) = refund_tx(&spk, &fee2);
        splice_verifier(&mut bad, &to_bob);
        finish_refund(&mut bad, &prev_bad);
        refuse(&node, &mut rec, &net, label, (&bad, &prev_bad), (&to_bob, &prev_b), JET, &[0]);
    }
    let refund_id = mine(&node, &mut rec, "R/alice_takes_the_rest_back_into_her_user_covenant", &refund, serde_json::json!({
        "verifier_stack_bytes": rw, "verifier_cost_milli_wu": rc, "verifier_budget_wu": rw * 4 + 50,
        "leaf": programs::shape_for(3, 4).unwrap().name(),
    }));
    verifier = coin_at(&node, &refund_id, 0);
    assert_eq!(coin_at(&node, &refund_id, 1).txout.script_pubkey, cu_alice);

    // ======================================================== W: a whole fill
    // alice's change into a second order, filled whole: the A to bob, nothing rests.
    let terms2 = OrderTerms { expiry: node.height() + 1_000, ..terms };
    let order2 = ctx.order(terms2, &alice);
    let fee3 = fees.pop().unwrap();
    let mut e2 = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![txin(verifier.op), txin(alice_change.op), txin(fee3.op)],
        output: vec![
            out(asset_v, q, &cv),
            out(asset_a, 40_000_000, &order2.script_pubkey()),
            out(asset_a, alice_change.value() - 40_000_000, &cu_alice),
            out(asset_fee, fee3.value() - FEE, &fee_spk),
            TxOut::new_fee(FEE, asset_fee),
        ],
    };
    let prev = vec![verifier.txout.clone(), alice_change.txout.clone(), fee3.txout.clone()];
    attach_policy_verifier(&ctx, &mut e2, &prev, &PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::User)],
        outputs: vec![(1, AOutput::Order { owner: None, terms: terms2 }), (2, AOutput::Change)],
    }, true).unwrap();
    sign_user_input(&ctx, &mut e2, &prev, 1, &alice_sk).unwrap();
    sign_fee_input(&net, &mut e2, &prev, 2, &fee_sk).unwrap();
    let e2_id = mine(&node, &mut rec, "W/alice_moves_A_into_a_second_order", &e2, serde_json::json!({}));
    verifier = coin_at(&node, &e2_id, 0);
    let o3 = coin_at(&node, &e2_id, 1);
    let alice_rest = coin_at(&node, &e2_id, 2);
    let whole_price = (o3.value() as u128 * 3).div_ceil(2) as u64;
    let pay1 = pays.pop().unwrap();
    let fee4 = fees.pop().unwrap();
    let mut whole = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![txin(verifier.op), txin(o3.op), txin(pay1.op), txin(fee4.op)],
        output: vec![
            out(asset_v, q, &cv),
            out(asset_a, o3.value(), &cu_bob),
            out(asset_b, whole_price, &maker_spk),
            out(asset_b, pay1.value() - whole_price, &payer_spk),
            out(asset_fee, fee4.value() - FEE, &fee_spk),
            TxOut::new_fee(FEE, asset_fee),
        ],
    };
    let prev = vec![verifier.txout.clone(), o3.txout.clone(), pay1.txout.clone(), fee4.txout.clone()];
    let (ww, wc) = attach_policy_verifier(&ctx, &mut whole, &prev, &PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::Order(terms2))],
        outputs: vec![(1, AOutput::Pay(bob))],
    }, true).unwrap();
    attach_order_spend(&net, &mut whole, &prev, 1, &order2, OrderPath::Whole, None).unwrap();
    sign_fee_input(&net, &mut whole, &prev, 2, &payer_sk).unwrap();
    sign_fee_input(&net, &mut whole, &prev, 3, &fee_sk).unwrap();
    let whole_id = mine(&node, &mut rec, "W/the_second_order_filled_whole_A_to_bob", &whole, serde_json::json!({
        "verifier_stack_bytes": ww, "verifier_cost_milli_wu": wc, "verifier_budget_wu": ww * 4 + 50,
        "leaf": programs::shape_for(4, 6).unwrap().name(),
    }));
    verifier = coin_at(&node, &whole_id, 0);

    // ======================================================== P: the policy still decides
    // alice and bob each put 50,000,000 A into an order with the same terms.
    // Then the issuer removes alice from the whitelist: her order is frozen
    // with her, while bob's still fills. Then the issuer drops the template
    // from the list: no order fills. Listing it again frees alice's order.
    let terms5 = OrderTerms { expiry: node.height() + 1_000, ..terms };
    let o5_inst = ctx.order(terms5, &alice);
    let ob_inst = ctx.order(terms5, &bob);
    let into_order = |ctx: &Ctx, v: &Coin, owner_sk: &[u8; 32], owner: XOnlyPublicKey, a: &Coin, inst: &GuardedOrderInstance, fee: &Coin| -> Transaction {
        let cu = ctx.cu_info(&owner).script_pubkey;
        let mut tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![txin(v.op), txin(a.op), txin(fee.op)],
            output: vec![
                out(asset_v, q, &ctx.cv_info().script_pubkey),
                out(asset_a, 50_000_000, &inst.script_pubkey()),
                out(asset_a, a.value() - 50_000_000, &cu),
                out(asset_fee, fee.value() - FEE, &fee_spk),
                TxOut::new_fee(FEE, asset_fee),
            ],
        };
        let prev = vec![v.txout.clone(), a.txout.clone(), fee.txout.clone()];
        attach_policy_verifier(ctx, &mut tx, &prev, &PolicySpend {
            sender: owner,
            inputs: vec![(1, AInput::User)],
            outputs: vec![(1, AOutput::Order { owner: None, terms: terms5 }), (2, AOutput::Change)],
        }, true).unwrap();
        sign_user_input(ctx, &mut tx, &prev, 1, owner_sk).unwrap();
        sign_fee_input(&net, &mut tx, &prev, 2, &fee_sk).unwrap();
        tx
    };
    let t = into_order(&ctx, &verifier, &alice_sk, alice, &alice_rest, &o5_inst, &fees.pop().unwrap());
    let id = mine(&node, &mut rec, "P/alice_moves_A_into_order_5", &t, serde_json::json!({}));
    verifier = coin_at(&node, &id, 0);
    let o5 = coin_at(&node, &id, 1);
    let alice_rest = coin_at(&node, &id, 2);
    let t = into_order(&ctx, &verifier, &_bob_sk, bob, &bob_a, &ob_inst, &fees.pop().unwrap());
    let id = mine(&node, &mut rec, "P/bob_moves_A_into_his_own_order_with_the_same_terms", &t, serde_json::json!({}));
    verifier = coin_at(&node, &id, 0);
    let ob = coin_at(&node, &id, 1);

    // An issuer update, through G(I), from `old` to `new`.
    let update = |old: &Ctx, new: &Ctx, v: &Coin, fee: &Coin| -> Transaction {
        let req = opendamp::txbuild::IssuerReq {
            verifier_outpoint: v.op,
            halt_spk: None,
            fee_utxo: (fee.op, asset_fee, fee.value()),
            fee_key,
            fee_amount: FEE,
            fee_change_spk: fee_spk.clone(),
        };
        opendamp::txbuild::complete_issuer_op(old, Some(new), &req, &issuer_sk, &fee_sk).expect("issuer update")
    };
    let wl_bob = vec![opendamp::dmt::Entry::unrestricted(bob.serialize())];
    let wl_both = vec![opendamp::dmt::Entry::unrestricted(alice.serialize()), opendamp::dmt::Entry::unrestricted(bob.serialize())];
    let ctx1 = Ctx::with_policy_and_contracts(net, params, issuer, wl_bob, &[], programs::NO_LIMIT, 1, listed.clone()).unwrap();
    let id = mine(&node, &mut rec, "P/issuer_update_seq1_alice_removed_from_the_whitelist", &update(&ctx, &ctx1, &verifier, &fees.pop().unwrap()), serde_json::json!({"pi": hex(&ctx1.pi)}));
    verifier = coin_at(&node, &id, 0);
    assert_eq!(verifier.txout.script_pubkey, ctx1.cv_info().script_pubkey);

    // A whole fill: [V, order, payer's B, fee] -> [V', A to `to`, B to the
    // maker (2), B change, fee change, fee].
    let whole_fill = |ctx: &Ctx, v: &Coin, o: &Coin, to: &Script, pay: &Coin, fee: &Coin| -> (Transaction, Vec<TxOut>) {
        let p = (o.value() as u128 * 3).div_ceil(2) as u64;
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![txin(v.op), txin(o.op), txin(pay.op), txin(fee.op)],
            output: vec![
                out(asset_v, q, &ctx.cv_info().script_pubkey),
                out(asset_a, o.value(), to),
                out(asset_b, p, &maker_spk),
                out(asset_b, pay.value() - p, &payer_spk),
                out(asset_fee, fee.value() - FEE, &fee_spk),
                TxOut::new_fee(FEE, asset_fee),
            ],
        };
        let prev = vec![v.txout.clone(), o.txout.clone(), pay.txout.clone(), fee.txout.clone()];
        (tx, prev)
    };
    let pay3 = pays.pop().unwrap();
    let fee7 = fees.pop().unwrap();
    // Bob's order fills under seq 1, its A back to bob: the control.
    let (mut bob_fill, bob_prev) = whole_fill(&ctx1, &verifier, &ob, &cu_bob, &pay3, &fee7);
    attach_policy_verifier(&ctx1, &mut bob_fill, &bob_prev, &PolicySpend {
        sender: bob,
        inputs: vec![(1, AInput::Order(terms5))],
        outputs: vec![(1, AOutput::Change)],
    }, true).unwrap();
    attach_order_spend(&net, &mut bob_fill, &bob_prev, 1, &ob_inst, OrderPath::Whole, None).unwrap();
    sign_fee_input(&net, &mut bob_fill, &bob_prev, 2, &payer_sk).unwrap();
    sign_fee_input(&net, &mut bob_fill, &bob_prev, 3, &fee_sk).unwrap();
    // Alice's order, the same in every byte but the coin: the builder refuses
    // her as the sender, and her order under bob's identity is refused in a block.
    let (mut frozen, frozen_prev) = whole_fill(&ctx1, &verifier, &o5, &cu_bob, &pay3, &fee7);
    let err = attach_policy_verifier(&ctx1, &mut frozen.clone(), &frozen_prev, &PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::Order(terms5))],
        outputs: vec![(1, AOutput::Pay(bob))],
    }, true).unwrap_err();
    rec.push(serde_json::json!({"proof": "P/builder_refuses_a_fill_of_a_frozen_owners_order", "error": err}));
    splice_verifier(&mut frozen, &bob_fill);
    attach_order_spend(&net, &mut frozen, &frozen_prev, 1, &o5_inst, OrderPath::Whole, None).unwrap();
    sign_fee_input(&net, &mut frozen, &frozen_prev, 2, &payer_sk).unwrap();
    sign_fee_input(&net, &mut frozen, &frozen_prev, 3, &fee_sk).unwrap();
    refuse(&node, &mut rec, &net, "P/neg_a_frozen_owners_order_filled_under_a_whitelisted_identity",
           (&frozen, &frozen_prev), (&bob_fill, &bob_prev), JET, &[0]);
    let id = mine(&node, &mut rec, "P/bobs_order_still_fills_under_seq1", &bob_fill, serde_json::json!({}));
    verifier = coin_at(&node, &id, 0);
    let bob_back = coin_at(&node, &id, 1);

    // Seq 2: alice restored, the template dropped from the list.
    let ctx2 = Ctx::with_policy(net, params, issuer, wl_both.clone(), &[], programs::NO_LIMIT, 2).unwrap();
    let id = mine(&node, &mut rec, "P/issuer_update_seq2_alice_restored_the_order_template_delisted", &update(&ctx1, &ctx2, &verifier, &fees.pop().unwrap()), serde_json::json!({"pi": hex(&ctx2.pi)}));
    verifier = coin_at(&node, &id, 0);
    // The control: bob pays alice 40,000,000 A from his user covenant, in the
    // same layout (four inputs, six outputs) as a whole fill.
    let pay4 = pays.pop().unwrap();
    let fee8 = fees.pop().unwrap();
    let bob_w = coin_at(&node, &whole_id, 1);
    assert_eq!(bob_w.value(), 40_000_000);
    let mut plain = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![txin(verifier.op), txin(bob_w.op), txin(pay4.op), txin(fee8.op)],
        output: vec![
            out(asset_v, q, &ctx2.cv_info().script_pubkey),
            out(asset_a, 40_000_000, &cu_alice),
            out(asset_b, 75_000_000, &maker_spk),
            out(asset_b, pay4.value() - 75_000_000, &payer_spk),
            out(asset_fee, fee8.value() - FEE, &fee_spk),
            TxOut::new_fee(FEE, asset_fee),
        ],
    };
    let plain_prev = vec![verifier.txout.clone(), bob_w.txout.clone(), pay4.txout.clone(), fee8.txout.clone()];
    attach_policy_verifier(&ctx2, &mut plain, &plain_prev, &PolicySpend {
        sender: bob,
        inputs: vec![(1, AInput::User)],
        outputs: vec![(1, AOutput::Pay(alice))],
    }, true).unwrap();
    sign_user_input(&ctx2, &mut plain, &plain_prev, 1, &_bob_sk).unwrap();
    sign_fee_input(&net, &mut plain, &plain_prev, 2, &payer_sk).unwrap();
    sign_fee_input(&net, &mut plain, &plain_prev, 3, &fee_sk).unwrap();
    // Alice's order filled whole to alice under seq 2.
    let (mut delisted, delisted_prev) = whole_fill(&ctx2, &verifier, &o5, &cu_alice, &pay4, &fee8);
    let err = attach_policy_verifier(&ctx2, &mut delisted.clone(), &delisted_prev, &PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::Order(terms5))],
        outputs: vec![(1, AOutput::Change)],
    }, true).unwrap_err();
    rec.push(serde_json::json!({"proof": "P/builder_refuses_an_order_the_policy_no_longer_lists", "error": err}));
    assert_eq!(o5.value(), 50_000_000);
    splice_verifier(&mut delisted, &plain);
    attach_order_spend(&net, &mut delisted, &delisted_prev, 1, &o5_inst, OrderPath::Whole, None).unwrap();
    sign_fee_input(&net, &mut delisted, &delisted_prev, 2, &payer_sk).unwrap();
    sign_fee_input(&net, &mut delisted, &delisted_prev, 3, &fee_sk).unwrap();
    refuse(&node, &mut rec, &net, "P/neg_an_order_filled_under_a_policy_that_no_longer_lists_its_template",
           (&delisted, &delisted_prev), (&plain, &plain_prev), JET, &[0]);
    let id = mine(&node, &mut rec, "P/bob_pays_alice_under_seq2", &plain, serde_json::json!({}));
    verifier = coin_at(&node, &id, 0);

    // Seq 3: the template listed again; alice's order fills.
    let ctx3 = Ctx::with_policy_and_contracts(net, params, issuer, wl_both, &[], programs::NO_LIMIT, 3, listed.clone()).unwrap();
    let id = mine(&node, &mut rec, "P/issuer_update_seq3_the_template_listed_again", &update(&ctx2, &ctx3, &verifier, &fees.pop().unwrap()), serde_json::json!({"pi": hex(&ctx3.pi)}));
    verifier = coin_at(&node, &id, 0);
    let (mut freed, freed_prev) = whole_fill(&ctx3, &verifier, &o5, &cu_bob, &pays.pop().unwrap(), &fees.pop().unwrap());
    attach_policy_verifier(&ctx3, &mut freed, &freed_prev, &PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::Order(terms5))],
        outputs: vec![(1, AOutput::Pay(bob))],
    }, true).unwrap();
    attach_order_spend(&net, &mut freed, &freed_prev, 1, &o5_inst, OrderPath::Whole, None).unwrap();
    sign_fee_input(&net, &mut freed, &freed_prev, 2, &payer_sk).unwrap();
    sign_fee_input(&net, &mut freed, &freed_prev, 3, &fee_sk).unwrap();
    let id = mine(&node, &mut rec, "P/alices_order_fills_again_under_seq3", &freed, serde_json::json!({}));
    verifier = coin_at(&node, &id, 0);
    let _ = bob_back;
    let ctx = ctx3;
    let cv = ctx.cv_info().script_pubkey.clone();

    // ======================================================== I: the issuer key
    // G(I) at input 0 satisfies the order's guard with no policy check: the
    // issuer alone fills an order on its terms and sends the A anywhere.
    let terms3 = OrderTerms { expiry: node.height() + 1_000, ..terms };
    let order3 = ctx.order(terms3, &alice);
    let fee5 = fees.pop().unwrap();
    let mut e3 = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![txin(verifier.op), txin(alice_rest.op), txin(fee5.op)],
        output: vec![
            out(asset_v, q, &cv),
            out(asset_a, 10_000_000, &order3.script_pubkey()),
            out(asset_a, alice_rest.value() - 10_000_000, &cu_alice),
            out(asset_fee, fee5.value() - FEE, &fee_spk),
            TxOut::new_fee(FEE, asset_fee),
        ],
    };
    let prev = vec![verifier.txout.clone(), alice_rest.txout.clone(), fee5.txout.clone()];
    attach_policy_verifier(&ctx, &mut e3, &prev, &PolicySpend {
        sender: alice,
        inputs: vec![(1, AInput::User)],
        outputs: vec![(1, AOutput::Order { owner: None, terms: terms3 }), (2, AOutput::Change)],
    }, true).unwrap();
    sign_user_input(&ctx, &mut e3, &prev, 1, &alice_sk).unwrap();
    sign_fee_input(&net, &mut e3, &prev, 2, &fee_sk).unwrap();
    let e3_id = mine(&node, &mut rec, "I/alice_moves_A_into_a_third_order", &e3, serde_json::json!({}));
    verifier = coin_at(&node, &e3_id, 0);
    let o4 = coin_at(&node, &e3_id, 1);
    let p3 = (o4.value() as u128 * 3).div_ceil(2) as u64;
    let pay2 = pays.pop().unwrap();
    let fee6 = fees.pop().unwrap();
    let mut by_issuer = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![txin(verifier.op), txin(o4.op), txin(pay2.op), txin(fee6.op)],
        output: vec![
            out(asset_v, q, &cv),
            out(asset_a, o4.value(), &p2tr_keypath_spk(&stranger)),
            out(asset_b, p3, &maker_spk),
            out(asset_b, pay2.value() - p3, &payer_spk),
            out(asset_fee, fee6.value() - FEE, &fee_spk),
            TxOut::new_fee(FEE, asset_fee),
        ],
    };
    let prev = vec![verifier.txout.clone(), o4.txout.clone(), pay2.txout.clone(), fee6.txout.clone()];
    let g_cb = ctx.verifier_spend().issuer_control.clone();
    let env = covenant_env(&net, &by_issuer, &prev, 0, ctx.g_cmr(), g_cb.clone());
    let (sig, _) = sign_bip340(&issuer_sk, &sig_all_digest(&env)).unwrap();
    attach_simplicity(&mut by_issuer, 0, &ctx.issuer, programs::issuer_witness(&sig).unwrap(), Some(&env), &g_cb).unwrap();
    attach_order_spend(&net, &mut by_issuer, &prev, 1, &order3, OrderPath::Whole, None).unwrap();
    sign_fee_input(&net, &mut by_issuer, &prev, 2, &payer_sk).unwrap();
    sign_fee_input(&net, &mut by_issuer, &prev, 3, &fee_sk).unwrap();
    mine(&node, &mut rec, "I/the_issuer_key_alone_fills_an_order_and_sends_A_to_a_plain_key", &by_issuer, serde_json::json!({
        "stated": "G(I) at input 0 runs no policy; the maker is paid the order's price",
    }));
    let _ = bob_a;
}
