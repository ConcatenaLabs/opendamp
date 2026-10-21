//! Contract templates a policy can whitelist (DESIGN.md section 2.4).
//!
//! A network-enforced asset can sit in a contract only if two things hold, and
//! neither is something the verifier can check at spend time about an arbitrary
//! program, so both are settled here, once, when a template joins this list:
//!
//! 1. **Every spending path of the template refuses a transaction without q of
//!    the asset's verifier asset V at input 0.** That is what brings the
//!    verifier into every transaction that moves the contract's coin, so the A
//!    that leaves it is scanned like any other. A template without such a guard
//!    lets anyone who satisfies its own rules send the asset anywhere: SeqDEX's
//!    plain `seqdex/order` is one, since a fill pays the maker and leaves the
//!    taker's output unconstrained. The guard reads the verifier asset and its
//!    amount from terms the verifier fixes, so no instance can name another.
//! 2. **The template names one owner key among its terms.** The verifier treats
//!    the contract's coin as that owner's: paying into it is a payment to the
//!    owner (or the sender's own change), and spending it is a transfer by the
//!    owner, so the whitelist, lockups, receive windows, the transfer limit and
//!    the blacklist reach a coin in a contract as they reach a user covenant.
//!
//! The verifier recognises an instance by rebuilding its script from the
//! template's commitment root and the terms, with the policy's fixed terms as
//! constants and the rest from the witness. No compiler runs at spend time.

use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};
use simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;
use simplicityhl::elements::taproot::ControlBlock;
use simplicityhl::elements::{AssetId, Script};
use simplicityhl::simplicity::Cmr;

use crate::programs::{asset_internal_bytes, AssetParams};
use crate::tapscript::{leaf_beside_data, CovenantSpendInfo};

/// One template the verifier can be told to recognise.
#[derive(Debug, PartialEq, Eq)]
pub struct ContractTemplate {
    /// The template's name in its descriptor.
    pub name: &'static str,
    /// The template hash its descriptor carries, which is how a policy lists it.
    pub template_hash: [u8; 32],
    /// The commitment root of the template's one program, in the descriptor's
    /// byte order (the order `jet::build_tapleaf_simplicity` hashes).
    pub cmr: [u8; 32],
    /// The verifier fragment that recognises an instance.
    pub fragment: &'static str,
    /// The verifier argument that carries `cmr`.
    pub cmr_param: &'static str,
}

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "a 32-byte hex constant");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("lower-case hex"),
    }
}

/// SeqDEX's order, guarded: `seqdex/guarded-order` in sequentia-contracts
/// (`templates/seqdex_guarded_order`). Its descriptor is vendored in
/// `contracts/seqdex_guarded_order.descriptor.json`, which a test reads to pin
/// these two constants.
pub const GUARDED_ORDER: ContractTemplate = ContractTemplate {
    name: "seqdex/guarded-order",
    template_hash: hex32("d68cecbf19c501abc78987833bec226e4a081ef19e484c0b060d3033b4239f60"),
    cmr: hex32("c676964fbb78174782e24f18b5fb3fdd65a844d7317ca43b84547807461ca659"),
    fragment: include_str!("../programs/contract_guarded_order.simf.in"),
    cmr_param: "ORDER_CMR",
};

/// Every template a policy may list. A template joins only with the guard and
/// the owner term above, proven on a node.
pub const WHITELISTABLE: &[&ContractTemplate] = &[&GUARDED_ORDER];

/// The contract templates one policy version lists, sorted by template hash.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Contracts {
    listed: Vec<&'static ContractTemplate>,
}

impl Contracts {
    /// A policy that lists no template: the asset can enter no contract.
    pub fn none() -> Self {
        Contracts { listed: Vec::new() }
    }

    /// The templates named by `hashes`. Refuses a hash this build cannot
    /// recognise, rather than publishing a policy that names a contract its
    /// verifier would not let the asset into, and refuses a repeat, so that a
    /// list has one encoding.
    pub fn from_hashes(hashes: &[[u8; 32]]) -> Result<Self, String> {
        let mut listed: Vec<&'static ContractTemplate> = Vec::with_capacity(hashes.len());
        for h in hashes {
            let t = WHITELISTABLE
                .iter()
                .copied()
                .find(|t| t.template_hash == *h)
                .ok_or_else(|| {
                    format!(
                        "contract template {} is not one this build can whitelist (known: {})",
                        crate::hexutil::hex(h),
                        WHITELISTABLE
                            .iter()
                            .map(|t| format!("{} {}", t.name, crate::hexutil::hex(&t.template_hash)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
            if listed.iter().any(|l| l.template_hash == *h) {
                return Err(format!(
                    "contract template {} is listed twice",
                    crate::hexutil::hex(h)
                ));
            }
            listed.push(t);
        }
        listed.sort_by_key(|t| t.template_hash);
        Ok(Contracts { listed })
    }

    pub fn is_empty(&self) -> bool {
        self.listed.is_empty()
    }

    pub fn templates(&self) -> &[&'static ContractTemplate] {
        &self.listed
    }

    pub fn lists(&self, t: &ContractTemplate) -> bool {
        self.listed.iter().any(|l| l.template_hash == t.template_hash)
    }

    /// The template hashes, sorted.
    pub fn hashes(&self) -> Vec<[u8; 32]> {
        self.listed.iter().map(|t| t.template_hash).collect()
    }

    /// The policy commitment to the list: 32 zero bytes for none, otherwise
    /// `H_"OpenDAMP/contracts/v1"(hash_1 || ... || hash_n)` over the sorted
    /// template hashes. It takes the fourth slot of `rules_root`, which a
    /// policy with no contracts leaves zero, so such a policy keeps its pi.
    pub fn commitment(&self) -> [u8; 32] {
        if self.listed.is_empty() {
            return crate::policy::EMPTY_COMMITMENT;
        }
        let tag = sha256::Hash::hash(b"OpenDAMP/contracts/v1").to_byte_array();
        let mut eng = sha256::Hash::engine();
        eng.input(&tag);
        eng.input(&tag);
        for t in &self.listed {
            eng.input(&t.template_hash);
        }
        sha256::Hash::from_engine(eng).to_byte_array()
    }
}

// ------------------------------------------------------------ the guarded order

/// The maker's own terms of a guarded order: everything but the four terms a
/// policy fixes (the asset sold, the guard's asset and amount, and the owner).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderTerms {
    /// The asset a fill pays in.
    pub asset_b: AssetId,
    /// The price: `rate_num` atoms of `asset_b` for every `rate_den` of A.
    pub rate_num: u64,
    pub rate_den: u64,
    /// The least a fill takes, and the least a remainder holds.
    pub min_lot: u64,
    /// SHA256 of the scriptPubKey every fill pays.
    pub maker: [u8; 32],
    /// The lock time from which the owner may take the coin back: below
    /// 500,000,000 a height, else a time.
    pub expiry: u32,
}

/// A guarded order's ten terms, as its data leaf holds them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardedOrderInstance {
    pub asset_a: [u8; 32],
    pub terms: OrderTerms,
    pub refund_key: [u8; 32],
    pub guard_asset: [u8; 32],
    pub guard_amount: u64,
}

impl GuardedOrderInstance {
    /// The instance a policy recognises: A sold, guarded by q of V, owned by
    /// `owner`.
    pub fn for_policy(params: &AssetParams, terms: OrderTerms, owner: &XOnlyPublicKey) -> Self {
        GuardedOrderInstance {
            asset_a: asset_internal_bytes(&params.asset_a),
            terms,
            refund_key: owner.serialize(),
            guard_asset: asset_internal_bytes(&params.asset_v),
            guard_amount: params.q,
        }
    }

    /// The data leaf's 196 bytes, each term big-endian at its width, asset ids
    /// in internal byte order.
    pub fn data(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(196);
        d.extend_from_slice(&self.asset_a);
        d.extend_from_slice(&asset_internal_bytes(&self.terms.asset_b));
        d.extend_from_slice(&self.terms.rate_num.to_be_bytes());
        d.extend_from_slice(&self.terms.rate_den.to_be_bytes());
        d.extend_from_slice(&self.terms.min_lot.to_be_bytes());
        d.extend_from_slice(&self.terms.maker);
        d.extend_from_slice(&self.terms.expiry.to_be_bytes());
        d.extend_from_slice(&self.refund_key);
        d.extend_from_slice(&self.guard_asset);
        d.extend_from_slice(&self.guard_amount.to_be_bytes());
        d
    }

    pub fn cmr() -> Cmr {
        Cmr::from_byte_array(GUARDED_ORDER.cmr)
    }

    /// The output's spend info and the order leaf's control block.
    pub fn spend_info(&self) -> (CovenantSpendInfo, ControlBlock) {
        leaf_beside_data(Self::cmr(), &self.data())
    }

    pub fn script_pubkey(&self) -> Script {
        self.spend_info().0.script_pubkey
    }
}

/// How a guarded order's coin is spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderPath {
    /// A fill in part: the remainder rests at output 2k+1.
    Partial,
    /// A fill of the whole coin.
    Whole,
    /// The refund, by the owner's signature, once the lock time reaches the
    /// expiry.
    Refund,
}

/// The four pruned programs of `contracts/seqdex_guarded_order.fills.json`, one
/// per path (two for the refund, by the kind of its expiry). A spend of a
/// guarded order needs no compiler: its program is one of these, and its
/// witness is the data leaf's bytes, the path and, for the refund, the
/// signature.
pub const GUARDED_ORDER_FILLS: &str = include_str!("../contracts/seqdex_guarded_order.fills.json");

pub fn guarded_order_program(path: OrderPath, expiry: u32) -> Result<Vec<u8>, String> {
    let fills: serde_json::Value =
        serde_json::from_str(GUARDED_ORDER_FILLS).map_err(|e| format!("fills.json: {e}"))?;
    let key = match path {
        OrderPath::Partial => "fill",
        OrderPath::Whole => "fill_whole",
        OrderPath::Refund if expiry < 500_000_000 => "refund_height",
        OrderPath::Refund => "refund_time",
    };
    let hex = fills["paths"][key]["program"]
        .as_str()
        .ok_or_else(|| format!("fills.json has no program for {key}"))?;
    crate::hexutil::unhex(hex)
}

/// The witness bit string of a guarded order's spend, packed into bytes: the
/// data leaf's bytes, PATH (`01` partial, `00` whole, `1` refund), then for the
/// refund the 64-byte signature, padded with zero bits.
pub fn guarded_order_witness(inst: &GuardedOrderInstance, path: OrderPath, sig: Option<&[u8; 64]>) -> Vec<u8> {
    let mut bits: Vec<bool> = inst
        .data()
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect();
    match path {
        OrderPath::Partial => bits.extend([false, true]),
        OrderPath::Whole => bits.extend([false, false]),
        OrderPath::Refund => bits.push(true),
    }
    if let Some(sig) = sig {
        bits.extend(sig.iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1)));
    }
    bits.chunks(8)
        .map(|c| c.iter().enumerate().fold(0u8, |a, (i, &x)| a | ((x as u8) << (7 - i))))
        .collect()
}

/// The four-element witness stack of a guarded order's spend.
pub fn guarded_order_stack(
    inst: &GuardedOrderInstance,
    path: OrderPath,
    sig: Option<&[u8; 64]>,
) -> Result<Vec<Vec<u8>>, String> {
    if (path == OrderPath::Refund) != sig.is_some() {
        return Err("the refund, and only the refund, carries a signature".into());
    }
    let (_, cb) = inst.spend_info();
    Ok(vec![
        guarded_order_witness(inst, path, sig),
        guarded_order_program(path, inst.terms.expiry)?,
        GUARDED_ORDER.cmr.to_vec(),
        cb.serialize(),
    ])
}
