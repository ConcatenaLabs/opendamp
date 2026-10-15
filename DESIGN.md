# OpenDAMP: network-enforced restricted assets on Sequentia

This is the OpenDAMP protocol. The covenant programs, the transaction builder
and the `opendamp` tool that implement it are in this repository, and
[`STATUS.md`](STATUS.md) states what the shipped covenants enforce and what they
deliberately do not (summarised in section 3.6 below). The policy library and
snapshot service are in `openampd`, in the
[`openamp`](https://github.com/ConcatenaLabs/openamp) repository.

Paths such as `src/...`, `test/...` and `contrib/...` are in the
[Sequentia node repository](https://github.com/ConcatenaLabs/Sequentia).


Revised after an adversarial review (2026-08-19) that found three defects and
one wrong claim, all fixed here and in the crate: dmt-v1's structural guards
were provable whitelist members, so a holder could burn regulated units to an
address the issuer never approved and nothing could recover them (they now hash
under their own domain byte); a receive window bound the sender's own change,
turning it into a spend prohibition; pi was not actually committed by the
covenant, so the "one policy version per address" claim in section 3.1 was not
true; and the invariant in section 2.1 -- that q of V never exists outside a
verifier covenant -- was load-bearing but unstated, with the halt in section 6
breaking it by design. The same pass removed the covenant's 22 kB of budget
padding, which is what section 2.2's shapes and the node's budget rule are for.
Companion to the [OpenAMP design](https://github.com/ConcatenaLabs/openamp/blob/main/DESIGN.md), which specifies the co-signed enforcement
model this protocol coexists with. OpenDAMP is the Sequentia adaptation of
DAMP, the Decentralized Asset Management Protocol proposed for Liquid by
Riabov and Chystiakov (Blockstream, August 2026). The protocol moves policy
enforcement from an online co-signer into a Simplicity covenant: ordinary
transfers require no issuer signature, holders supply policy proofs, and the
chain verifies them.

OpenDAMP does not replace OpenAMP. Enforcement is an issuance-time election
committed into the asset contract (and therefore into the asset id), chosen
per asset:

- `cosign` (OpenAMP): richest rule set, opt-in confidentiality from outside
  observers, transfer availability depends on the policy service.
- `damp` (OpenDAMP): transfers never depend on the policy service, the
  operator never signs a transfer, asset tags are explicit on every output.

This is the two-of-three trade recorded in section 9 of the [OpenAMP design](https://github.com/ConcatenaLabs/openamp/blob/main/DESIGN.md) made
into a product choice instead of a design argument.

## 1. Roles and assets

- The **issuer** creates the regulated asset A and controls an issuer key I
  (one x-only point; a FROST group key in production). The reissuance token
  for A is governed outside the protocol, but any later issuance of A must
  enter user covenants, or the issuer has created unregulated units.
- The issuer also creates a distinct **verifier asset** V. A valid verifier
  output carries a fixed amount q of V. Retaining V's reissuance authority
  lets the issuer create parallel verifier outputs as demand grows, which
  reduces contention.
- A **holder** controls an x-only key X and receives A in a user covenant
  C_U(X).

## 2. Covenant constructions

Both covenants are taproot outputs with the BIP341 NUMS internal key (no key
path) and Simplicity leaves at tapleaf version 0xbe. All tagged hashes use
the Elements taproot domains (`TapLeaf/elements`, `TapBranch/elements`,
`TapTweak/elements`). A Simplicity spend on Sequentia must present the
witness stack exactly as `[simplicity_witness, simplicity_program, CMR(32),
control_block]`; all dynamic data (keys, signatures, Merkle proofs) is
carried inside the Simplicity witness blob.

### 2.1 User covenant C_U(X)

Following the DAMP paper's Taproot state construction: let U be the Elements
TapLeaf hash of the fixed Simplicity user program, K the NUMS key, and

    D(X)   = H_TapData(X)
    R_U(X) = TapBranch(U, D(X))
    C_U(X) = P2TR(K, R_U(X))

One fixed program serves every holder; changing X changes only the address.
The program recomputes C_U(X) from the witness-supplied X (via the
`tapdata_init` / `tappath` jets and the taproot-construction jets) and
compares it with its own locking script, so a witness cannot substitute
another key. It then checks:

1. BIP340Verify(X, sig_all_hash(T), sigma_X) over the spending transaction.
2. The current input carries explicit asset A and is not input zero.
3. Input zero carries explicit verifier asset V in amount q.

These checks establish custody only. Policy is enforced by the verifier
covenant spent in the same transaction.

**What check 3 does not say.** It asks that *some* output carrying q of V sits
at input zero, not that the output is a verifier covenant, and U cannot ask for
more: C_V(pi) is a different address for every policy version while U is fixed
for the life of the asset and committed inside every C_U address. Confinement
therefore rests on an invariant no covenant can check:

> q units of V must never exist outside a verifier covenant.

If it is ever broken, whoever controls that output can place it at input zero
and let any holder spend their C_U with no whitelist, no blacklist, no limit and
no window, on their own signature alone. This is the paper's construction (3.2)
and the paper's assumption (5.1); it is stated here because it is load-bearing
and easy to break by accident. Two operational consequences, both enforced by
the tooling rather than left to a runbook, are in section 6.

Do not try to close this in the covenant. An earlier revision of U required
output zero to recreate input zero's script unless the issuer signed; a holder
of stray V simply pays it back to the same address, which satisfies the equality
exactly. Simplicity exposes another input's script pubkey but not which leaf it
executed, so nothing a fixed U can read distinguishes a real C_V(pi) from an
imitation.

### 2.2 Verifier covenant C_V(pi)

Let P(pi) be the primary spending path instantiated with policy commitment
pi, and G(I) the issuer path requiring a BIP340 signature under I over
sig_all_hash. R_V(pi) commits to both; C_V(pi) = P2TR(K, R_V(pi)). The NUMS
key provides no key-path spend. On the primary path, P(pi) checks:

1. Its input is transaction input zero and carries q units of V.
2. Output zero returns q units of V to the same C_V(pi).
3. At least one input is a C_U(X) input (which independently requires its
   owner's signature, so only holders can advance the verifier output).
4. Every output exposes an explicit asset identifier, EXCEPT outputs for
   which `output_is_fee` holds (see 2.3). Every output carrying A pays
   C_U(Y) for its witness-supplied recipient key Y, computed with the
   taproot-construction jets.
5. All enabled policy predicates hold (section 3).

Checks 3 and 4 are stronger than the paper's, and check 4 has an exemption the
paper does not need:

- **The sender is proven once.** All regulated inputs of a transfer belong to
  one owner -- the transfer limit needs that twice over, since a limit is per
  sender and change is identified relative to one -- so P(pi) verifies one
  whitelist membership proof for the sender, applies their lockup, and then
  requires every A input's script to be exactly C_U(sender). That is the same
  binding a per-input proof gave, it makes the single-sender rule structural,
  and it removes a 16-level Merkle fold and a taproot reconstruction from every
  input slot after the first.
- **Change is exempt.** An A output paying C_U(sender) is change: no membership
  proof, no receive window, no explicit value. A receive window restricts
  *acquisition*; applying it to a sender's own change turns it into a spend
  prohibition, so a holder inside a Reg S window could not transact at all
  unless a UTXO happened to equal the payment exactly. The sender's standing was
  established once already, and retaining your own coins is not an acquisition.

**Shapes.** The scans are bounded unrolls: the covenant commits to maximum input
and output counts, checked against `num_inputs` and `num_outputs`. Because
Simplicity's cost bound is *static* over the whole program DAG and does not
shrink when a slot goes unused, a single program sized for the widest transfer
charges every ordinary transfer for slots it never touches. So P is compiled
once per **shape** -- a pair (N_max_inputs, N_max_outputs) -- and every shape is
a leaf of the same C_V(pi) taptree. The address does not depend on which leaf a
spender uses; each leaf asserts its own bounds, so a narrow leaf cannot be used
for a wide transaction; and a wallet picks the narrowest leaf that fits.

The menu, with the canonical transfer given the shallow leaf so its control
block is shortest:

| leaf   | inputs | outputs | for                                            |
|--------|--------|---------|------------------------------------------------|
| `p3x5` | 3      | 5       | verifier, 1 regulated, fee; verifier, payment, change, fee-change, fee. **Canonical.** |
| `p3x4` | 3      | 4       | the same with an exact fee UTXO                 |
| `p4x6` | 4      | 6       | two regulated inputs, or two payments           |
| `p5x7` | 5      | 7       | consolidation: three regulated inputs           |

No shape has fewer than three inputs, and that is forced rather than chosen: a
transfer cannot pay its fee in A, and the verifier input's q of V is returned
whole to output zero, so the fee must come from an ordinary input that is
neither.

**Budget.** Execution cost is bought with witness bytes. Sequentia grants
`SIMPLICITY_BUDGET_PER_WITNESS_BYTE` = 4 weight units of execution per witness
byte (`src/script/script.h`), against Elements' one, capped at 4,000,050. Under
that rule every shape's functional witness pays for its own static cost with a
margin of 1.3x to 2.3x, and the covenants carry **no padding**. Under the
one-to-one rule they are unspendable by design, which is the correct failure:
they would otherwise need tens of kilobytes of inert bytes in every transfer.

**On the live testnet the wider budget starts at height 101,810**, a little over
a day past the tip at release. The rule only ever accepts more, so it needs no
activation gate for correctness; the flag day exists because that chain is
running and has other operators. Ungated, the fork would fire the instant anyone
broadcast a spend the old budget could not pay for, and every node still on the
old rule would reject that block and fork off, on a date nobody could predict.
Until 101,810 the new binary enforces the old budget, so upgrading early is safe
and OpenDAMP covenants are unspendable there; every fresh chain -- regtest,
mainnet, a re-genesised testnet -- has the wider budget from genesis.
The measured canonical transfer is a 3,634-byte verifier witness and a
726-byte user witness, against 26,830 and 633 for the padded single-shape
program it replaced.

### 2.3 Sequentia delta: any-asset fees

Sequentia has no privileged fee asset. Fee outputs (empty scriptPubKey) may
carry any accepted asset, so the confinement scan must tolerate them, with
one exception that the covenant enforces absolutely: **an output that is a
fee output must not carry asset A.** This makes Rule 1 of the OpenAMP design
(a restricted asset never appears in a fee output) consensus-enforced for
OpenDAMP assets. Holders pay fees in an ordinary asset directly, or through
the fee-conversion pattern with any registered fee broker; the conversion
output to the broker is an ordinary C_U output of A and passes confinement.

### 2.4 Confidentiality position

Asset identifiers must be explicit on every output the scan reaches; there
is no unblind jet, so the covenant can only police what it can read. Value
commitments may remain confidential on outputs and inputs that no enabled
policy predicate needs to read; the transfer-limit predicate requires
explicit values on payments to other owners while sender change may stay
blinded. Issuers who need holdings hidden from outside observers should
elect `cosign` instead; this is the point of offering both.

## 3. Policy commitment and predicates

### 3.1 Commitment

    pi = H_"OpenDAMP/policy/v1"( version_u8 || asset_A || seq_u64 || rules_root )

`seq` increments on every policy update. `rules_root` is a Merkle root over
the enabled predicate commitments in fixed order (absent predicates commit
to the empty hash).

pi is a compile-time parameter of the verifier program and enters its DAG, so
C_V(pi) commits to exactly one policy **version**. This is worth stating
precisely because the near-miss is silent: the covenant enforces the whitelist
root, the blacklist root and the limit *directly*, and if only those reached the
program then two snapshots with identical rules and different sequence numbers
would produce the same address, and a rollback would be indistinguishable on
chain from the version it rolled back to. Committing pi costs one 256-bit
comparison (measured: 2,807 milli-weight-units) and closes that.

### 3.2 Predicate: blacklist by outpoint (the freeze mechanism)

**Enforced.** Non-membership is proved with an INTERVAL tree rather than
adjacency over proof indices, which a dense tree cannot express cheaply: a leaf
is `SHA256(0x02 || lo || hi)` and absence is one ordinary membership proof of
the bracketing interval plus two strict 256-bit comparisons. See
[`SPEC-dmt-v1.md`](SPEC-dmt-v1.md).

For an input outpoint (t, v), the policy key is k_out = SHA256(t || BE32(v)).
The issuer commits to a dmt-v1 interval tree ([`SPEC-dmt-v1.md`](SPEC-dmt-v1.md))
containing blacklisted outpoints. An earlier draft of this document reserved
`smt-v1` and `cmt-v1`; neither fits the Simplicity budget at depth 256, which is
why dmt-v1 exists, and a snapshot declaring one is refused rather than accepted
into an address no holder could spend. Each regulated input supplies a non-membership proof
against the committed root. A listed UTXO cannot satisfy the verifier; an
unlisted UTXO spends without contacting the issuer.

This is how a court-order freeze works for an OpenDAMP asset: the issuer
publishes a policy update adding the outpoint, effective for all spends
after the verifier output moves to C_V(pi'). Consensus-level supervision
(supervised assets) is not used for OpenDAMP assets: a C_U output is not a
single-owner script, so a supervision freeze would not bind it, and the
blacklist provides the same power with per-outpoint granularity and a
public, signed, versioned history.

### 3.3 Predicate: whitelist by owner key

Membership proofs keyed by stable owner x-only keys, which permits repeated
transfers among approved holders. The verifier checks BOTH the owners of
regulated inputs and the recipients of regulated outputs, so removing a key
from the whitelist stops that holder spending as well as receiving: that is
the in-covenant freeze, and it is per holder rather than a halt. A whitelist
entry is a key plus two height bounds, `send_after` (the lockup, binding an
input owner) and `recv_after` (the receive window, binding an output
recipient), committed INSIDE the leaf so the proof that a key is approved also
proves which windows bind it and a holder cannot shorten their own lockup. The
tree is dmt-v1, a sorted dense Merkle tree of depth 16, specified byte for byte
in [`SPEC-dmt-v1.md`](SPEC-dmt-v1.md). The list is
compiled from SeqPal ID eligibility stamps by the registrar: enforcement is
on-chain, vetting stays exactly where it is in the cosign model. Newly
verified investors become spendable-to when the issuer publishes the next
list version; publication cadence is a registrar service parameter.

### 3.4 Predicate: transfer limit

All regulated inputs must belong to the authenticated sender X; payments to
other owners must use explicit values and their sum must not exceed the
committed limit. Outputs returning to X are change and may stay blinded.

### 3.5 Predicate: height windows

Lockups and receive windows (the Reg S pattern) are enforced by requiring
the transaction's locktime to prove a height bound (`lock_time` /
`parse_lock` jets) combined with list membership keyed by owner class. A
covenant cannot read the chain height directly; the locktime proof is the
standard reduction.

### 3.6 What stays off the chain

Every predicate this document specifies is enforced on chain; what follows is
what it deliberately does not specify. Velocity, holder caps, and any rule
requiring global chain state stay registrar-maintained: they are approximated by policy updates at issuer
cadence, not enforced per transfer. Offering documents for an OpenDAMP asset
must state which rules are covenant-enforced and which are registrar
commitments. Issuers needing the full stateful rule set per transfer elect
`cosign`.

## 4. Snapshot publication and data availability

A Merkle root authenticates proofs but cannot generate them. Holders (or
mirrors) must retain the current snapshot to spend without the issuer's
service; loss of the data halts the primary path until it is recovered or
the issuer publishes an update. The registrar therefore treats snapshot
publication as a first-class obligation:

    snapshot/v1 = {
      "v": 1, "asset": A, "verifier_asset": V, "q": q,
      "pi": <hex>, "seq": n, "prev_pi": <hex or null>,
      "tree": "dmt-v1",
      "predicates": {
        "blacklist": { "root": <hex>, "entries": [...] | "url": ... },
        "whitelist": { "root": <hex>, "entries": [...] | "url": ... },
        "limit": <u64 or null>,
        "windows": [...]
      },
      "issuer_sig": <BIP340 over H_"OpenDAMP/snapshot/v1"(canonical-json-without-sig)>
    }

Every version is content-addressed and published through the asset registry
and the operator transparency log (hash-chained, anchored on-chain), and
served over a subscription endpoint wallets poll. The genesis snapshot's
hash is committed in the asset contract (section 5), so pi_0 is verifiable
from the asset id alone.

## 5. Contract binding

The registry contract's `openamp` block gains:

    "enforcement": "damp",
    "verifier_asset": <asset id of V>,
    "verifier_amount": q,
    "issuer_update_key": <x-only I>

As with every contract field, this is committed into the issuance entropy:
the asset id proves its own enforcement model, its verifier asset, and the
issuer key that may update the policy. Enforcement can never be retrofitted
in either direction.

**The genesis policy is deliberately NOT in the contract.** An earlier draft
committed `genesis_policy` and `genesis_snapshot_hash` here, which cannot
work: pi commits to asset A's id (section 3.1), and A's id commits to its
contract, so a contract carrying pi_0 would have to contain a hash of itself.
The setup order resolves it without a circular commitment:

1. Issue V (q units) to an ordinary wallet output. V's id depends on nothing
   about A.
2. Issue A with the block above naming V, minting straight into user
   covenants.
3. Compute pi_0 from A's now-known id and the genesis predicate roots.
4. Move the q units of V into C_V(pi_0). Only from this point can any
   transfer of A settle, so there is no window in which A moves unpoliced.
5. Publish snapshot seq 0.

The genesis policy is instead authenticated the same way every later policy
is: by the snapshot's issuer signature and the transparency log, with the
verifier output on chain being the binding fact a holder verifies against.

## 6. Issuer operations

- **Update**: spend C_V(pi) through G(I), create C_V(pi') with q of V, and
  publish snapshot seq+1 before or at broadcast. Wallets treat a verifier
  output whose pi has no published snapshot as unspendable-by-them and alert.
- **Halt**: BURN V through G(I), to a bare `OP_RETURN`. This is the pause
  analog. It must be a burn and not an ordinary address, because of the
  invariant in section 2.1: q of V parked at a spendable output is a standing
  bypass of the entire policy for whoever holds that key. An OP_RETURN output
  can never be an input, so a burn leaves no such output in existence and A is
  frozen, which is what a halt is supposed to mean. Resuming means reissuing V.
  `IssuerReq::halt_to_burn` is the supported path and
  `halt_leaves_live_verifier_asset` names the alternative for a caller that
  insists on it.
- **Parallel verifier outputs**: with retained V reissuance authority the
  issuer may run N verifier outputs to reduce the spending race. Keeping
  their policy versions consistent during an update is an operational
  runbook item: update all outputs in one transaction where possible, or
  publish the union semantics (a transfer is valid under the pi its chosen
  verifier input commits to).

  **V's reissuance authority is as sensitive as the issuer key I.** Minting q of
  V to an ordinary address is a complete bypass of the policy by the route in
  section 2.1, so retaining that authority to run parallel outputs means
  retaining a second key of the same criticality, held the same way. Destroying
  it after setup is the safer default, at the cost of a single verifier output
  and the spending race that comes with it.
- **Redemption**: the primary path has no redemption exit. The issuer path
  still permits an informal exit: a collaborating holder and the issuer can
  move A outside confinement (both signatures required; a holder who does
  not consent is unaffected). A dedicated redemption branch with fixed rules
  (holder signature plus issuer signature, outputs only to a fixed
  redemption covenant or a provably unspendable burn) is planned for v2.

## 7. Security considerations

Inherited from the DAMP paper with Sequentia specifics:

- **Custody**: the issuer alone cannot spend a holder's balance on any path;
  every user input requires its owner's signature. Compromise of I permits
  policy revocation or denial of service, not theft. I should be a FROST
  group key.
- **Contention**: a single verifier output is a spending race; see parallel
  outputs above. An optional coordinator can order transactions without
  becoming an authorization service, at the cost of potential MEV.
- **Data availability**: section 4. The registrar's snapshot service going
  down does not halt transfers for holders who retained the snapshot; that
  is the tier's headline property.
- **Anyone-can-spend hazard**: an unenforced 0xbe leaf is anyone-can-spend.
  Never fund an OpenDAMP covenant on a chain where `getdeploymentinfo` does
  not report simplicity active. On Sequentia: mainnet always-active; the
  live testnet is active (BIP9 bit 21, since height 89,856); a custom chain
  such as `elementsregtest` needs `-evbparams=simplicity:-1:::`, which makes
  it active from genesis. `simplicity:0:::` only starts signalling and leaves
  the leaf anyone-can-spend until height 384 at the earliest. See
  [`simplicity.md`](https://github.com/ConcatenaLabs/Sequentia/blob/master/doc/sequentia/simplicity.md).
- **Budget exhaustion**: with no padding, every shape has to pay for its own
  static cost out of the proofs it genuinely carries. The binding case is the
  *smallest* legitimate witness -- the sender proof, one regulated input, one A
  output -- because anything richer buys more budget against an unchanged cost.
  `tests/cost_profile.rs` asserts that margin per shape (1.3x to 2.3x today) and
  fails rather than letting a widened scan produce an unspendable leaf.
- **Confinement rests on an unverifiable invariant**: q of V must never exist
  outside a verifier covenant (section 2.1). Halt burns V and V's reissuance
  authority is key-critical (section 6); neither is optional.
- **Fixed input-zero position**: functionally limiting (the paper notes it);
  accepted for v1.
- **Throughput**: a single verifier output serialises every transfer of an
  asset, so contention, not size, is the first ceiling a busy asset hits. Size
  is the second: a canonical transfer measures 1,582 vB (the node's own vsize,
  asserted in the regtest suite) against 89,999 vB of real block payload, so 56
  restricted transfers fit in a block. The padded single-shape program managed
  12.

## 8. Toolchain and milestones

Simplicity programs are written in SimplicityHL and compiled outside this
repository; the node vendors only the Simplicity interpreter and jets. A
template registry pins `program_id -> CMR` for the fixed user program and
each verifier program version; wallets and the registrar verify CMRs against
this registry, never against locally compiled artifacts.

- **M0 (this document)**: protocol, commitment and snapshot formats, contract
  binding.
- **M1**: U and P(pi) in SimplicityHL; golden CMR vectors; functional test on
  elementsregtest proving transfer, confinement refusal, blacklist refusal
  and non-membership spend, whitelist, limit, issuer update, halt.
- **M2**: policy-commitment library and snapshot service in the operator
  daemon; `enforcement` election plumbed through issuance (refused with a
  capability error until M1 ships); registry validation of the new contract
  fields.
- **M3**: wallet support (sig_all_hash signing, proof assembly from
  snapshots, SPK-based UTXO discovery as a descriptor variant); venue
  integration spec update.
- **M4**: testnet pilot: one live asset through issue, transfers with the
  policy service deliberately stopped, freeze by policy update, unfreeze,
  and an issuer halt drill.
