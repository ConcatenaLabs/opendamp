# opendamp

The OpenDAMP covenants and the tool that drives them. OpenDAMP is network
enforcement for a regulated asset on Sequentia: the asset's policy -- who may
hold it, which coins are frozen, how much may move in one transfer, from which
height -- is enforced by Simplicity covenants that every node runs, with no
server in the path of a transfer. This crate holds the covenant programs, the
library that builds and signs transfers under them, and `opendamp`, the
command-line tool an issuer, a holder or a counterparty uses to do so offline.

Two covenants carry the scheme. `C_U(owner)` holds a holder's coins of the
asset; every spend of it must be accompanied by the asset's **verifier**,
`C_V(pi)`, at input 0 of the same transaction, and the verifier is the program
that checks the policy `pi` against every regulated input and output. The
issuer moves the verifier to a new policy with an update, and stops the asset
altogether with a halt. A policy can also list **contract templates** the
asset may enter, such as SeqDEX's guarded order: the verifier then recognises
an order owned by a whitelisted holder as that holder's coin, and checks
everything the order pays out. `programs/*.simf` are the programs;
[`DESIGN.md`](DESIGN.md) is the design,
and `STATUS.md` here is the record of what is proven against a node.

## Build and test

```sh
cargo build --release          # target/release/opendamp
cargo test                     # the offline tests: builder, covenants, cosigner
cargo test --test regtest -- --ignored --nocapture   # the proof against a node
cargo test --test regtest_contracts -- --ignored --nocapture   # the asset in an order
```

The regtest proof spawns `sequentiad`: `$OPENDAMP_NODE_BIN`, or
`../Sequentia/src/sequentiad`, a node checkout beside this one. It also runs
sequentia-contracts' `token-covenants` tool for the verifier asset's token:
`$OPENDAMP_TOKEN_COVENANTS`, or
`../sequentia-contracts/tools/token-covenants/target/release/token-covenants`
beside this checkout. `regtest_contracts` needs the node alone; it writes every
proof's outcome to `$OPENDAMP_CONTRACTS_RECORD` when that is set.

## The tool

Every command takes `--snapshot FILE`, the policy snapshot in its published
`snapshot/v1` form ([`DESIGN.md`](DESIGN.md) section 4), the document `openampd`
publishes and hands an issuer as `derive_snapshot`: the asset, its verifier
asset and amount `q`, `pi`, the policy sequence number and `prev_pi`, the
whitelist (bare keys, or keys with `send_after` and `recv_after` heights) and
the blacklist, each with its `root`, the transfer `limit`, `windows` (empty: no
program reads class windows; height bounds live in the whitelist entries),
`contracts` when the policy lists contract templates (their template hashes, in
ascending order) and, once published, `issuer_sig`. A blacklist entry is an outpoint's policy key,
`SHA256(txid || BE32(vout))` with the txid in internal byte order, in hex;
`opendamp outpoint-key --txid T --vout N` prints it. Beside the snapshot the
document carries what a derivation needs and the snapshot does not: the
issuer's `issuer_update_key`, the `network` (`testnet` or `regtest`), and on
regtest the chain's `genesis` hash. `openampd`'s `derive_snapshot` and
`derive_current` carry all three; `examples/snapshot-seq0.json` is a document
in this form, and `examples/snapshot-contracts.json` the same policy listing
the guarded order.

The tool recomputes both roots and `pi` from the entries and refuses a
document whose declared `pi` or roots disagree with them, a list published by
`url` rather than inline, a non-empty `windows`, a contract list out of order
or naming a template this build cannot recognise, and any field it does not
know, so a document can never state a rule the programs do not enforce.
Nothing needs a node: the snapshot plus explicit coin data is enough, and what
a command prints is broadcast with `sendrawtransaction`.

| command | what it does |
|---|---|
| `derive --snapshot S [--owner X]...` | the policy's addresses and program identities: `C_V(pi)`, every `C_U(owner)`, the CMRs of the user, verifier and issuer programs, `pi` itself |
| `registry --snapshot S` | the CMR pinning document a wallet or a registrar verifies programs against (`vectors/addresses.json` is the published one) |
| `vectors --snapshot S [--out FILE]` | golden derivation vectors, so an independent implementation can check its taproot construction byte for byte |
| `transfer-build --snapshot S --request R` | an unsigned transfer from a request file, with the sighash of each sender input, the outputs it spends (`prevouts`), and the whitelist proofs resolved -- what a signer that holds the key elsewhere needs |
| `transfer-finalize --snapshot S --request R` | the same transfer built, signed with `sender_privkey` and `fee.privkey` from the request, and every covenant run locally before it is printed |
| `transfer-cosign --snapshot S --transaction T --sender-privkey HEX [--recipient X]... [--out FILE]` | sign the OpenDAMP inputs of a transaction somebody else laid out (below) |
| `issuer-update --snapshot S --next-snapshot S' --request R --issuer-privkey HEX` | move the verifier from policy `S` to policy `S'` |
| `outpoint-key --txid T --vout N` | the policy key of an outpoint, as a snapshot's blacklist lists it |
| `order-address --snapshot S --owner X --terms FILE` | the guarded order this policy recognises for an owner and a maker's terms: its address, script, data leaf and control block |
| `contract-verifier --snapshot S --transaction T [--out FILE]` | the verifier's witness for a transaction somebody else laid out that moves the asset into, inside or out of a listed contract (below); it signs nothing |
| `halt --snapshot S --to-spk HEX --request R --issuer-privkey HEX` | send the verifier asset out of the covenant, which stops every transfer of the asset; a halt must burn it (an `OP_RETURN` script), for the reason in the issuer section of `src/txbuild.rs`, and records the burned verifier in V's token covenant (below) |

A **request file** (`examples/transfer-request.json`) names the sender's key
and coins, the recipient and amount, the verifier's outpoint, and the fee coin
-- an ordinary asset, since the covenant forbids paying a fee in the regulated
one -- with its key and where its change goes. `locktime` is the height the
transfer claims, which is how a lockup or a receive window is satisfied.
`examples/issuer-request.json` is the issuer's, which needs only the verifier
outpoint and a fee coin.

### Halting and resuming

V's reissuance token is held by the `sequentia/verifier-token` covenant of the
[`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts)
repository (its `docs/verifier-token.md`), from the issuance on. It reissues
exactly `q` of V, signed by the issuer key, only into the verifier covenant it
last recorded. That repository's `token-covenants` tool builds its spends; the
issuer keeps the token covenant's instance file (`token-covenants
verifier-token instance`) beside the snapshots.

**Halt.** The request carries a `verifier_token` block naming the token
covenant's coin:

```json
"verifier_token": {
  "txid": "...", "vout": 1, "asset": "<V's reissuance token>", "value": 100000000,
  "script_pubkey": "<the coin's scriptPubKey>",
  "recorded": "<scriptPubKey of the verifier the coin records now>",
  "successor_spk": "<token-covenants verifier-token address --instance I --verifier <C_V(pi) scriptPubKey>>"
}
```

`opendamp halt --to-spk 6a ...` then burns V from `C_V(pi)` at input 0 and
spends the token covenant at input 1, its successor at output 1 recording
`C_V(pi)`, and prints `{tx, prevouts, verifier}` with input 0 and the fee
input signed. The issuer key's record signature goes in with

```sh
token-covenants verifier-token record --instance I --key-file ISSUER_KEY < halt.json
```

which checks input 0 holds exactly `q` of V and output 1 records its script,
and prints the finished transaction to broadcast. A halt without the block is
refused unless `--unrecorded yes` is given, for an asset whose V token is in no
covenant: a halt that does not record leaves the covenant recording an older
verifier, and a resume would restore that older policy. `issuer-update` takes
the same block, to record the verifier an update leaves.

**Resume.** `token-covenants verifier-token build --instance I --key-file
ISSUER_KEY` with a `resume` request reissues `q` of V into the recorded
verifier and returns the transaction with its fee coins for the wallet to sign
(that tool's `README.md` gives the request). The asset resumes under the policy
it was halted at; an update moves it on. Resume only a halted asset, unless a
second verifier under the same policy is meant: a live verifier at the
recorded script would otherwise gain a parallel twin, and a halt has to burn
every one.

### Signing a transaction you did not build

A transfer is not always this tool's to lay out. A settlement of a Pignus
repurchase, for one, spends the verifier at input 0 and the lender's `C_U` at
input 2 alongside two coins that are not OpenDAMP's at all, in an order the
bond covenant dictates. `transfer-cosign` owes such a transaction exactly what
the sender owes their own transfer: a signature over each of their `C_U`
inputs, and the verifier witness proving them and every recipient. It touches
nothing else, so a party who signed before the sender loses nothing.

`--transaction T` is a JSON document with `tx`, the transaction's hex, and
`prevouts`, the outputs its inputs spend in input order, each as `{asset,
value, script_pubkey}`; whatever else the document carries comes back with it.
`transfer-build` prints `prevouts` in this form. The candidates for an output
of the asset are every whitelisted key plus any named with `--recipient`.
Before signing, the tool says what it is about to sign -- each coin of the
asset spent from the sender's `C_U`, each output of it and whose `C_U` it
pays, the totals, the height claimed -- and names what a node would only
reject: a verifier of
another policy at input 0, a regulated input that is not the sender's, an
output of the asset paying no candidate's `C_U`, a payment over the limit, a
lockup or receive window the transaction's `nLockTime` does not claim. Every
covenant is run locally before the result is written.

### Contracts

A policy's `contracts` list names the templates the asset may enter. The one a
policy can list is `seqdex/guarded-order`, SeqDEX's order with a guard: every
fill and refund needs exactly `q` of the asset's verifier asset at input 0, so
the order moves only beside the verifier. The template, its pruned programs
and its vectors are vendored in `contracts/` from
[`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts)
(`docs/seqdex-guarded-order.md` there). The policy fixes four of its terms: it
sells this asset, its guard is this asset's verifier asset and `q`, and its
refund key is its **owner**, a whitelisted holder. The maker chooses the rest.

The verifier treats an order as its owner's coin:

- Paying into an order the sender owns is change.
- Paying into an order another holder owns is a payment to that holder: their
  proof and receive window apply, and the amount counts against the limit.
- Spending an order, by a fill or by its refund, is a transfer by its owner:
  the owner's whitelist entry and lockup, the single-sender rule and the
  blacklist apply, and every output of the asset is scanned like any other.

A fill therefore needs nothing from the maker. Anyone holding the snapshot
builds the verifier's witness, and the order's own witness is its terms and
path, with no compiler (`contracts::guarded_order_stack`).

`order-address --terms FILE` takes the maker's terms as
`{asset_b, rate_num, rate_den, min_lot, maker, expiry}`. Here `maker` is the
SHA256 of the scriptPubKey every fill pays, and `asset_b` is in display hex.

`contract-verifier --transaction T` takes `tx` and `prevouts` as
`transfer-cosign` does, together with:

- `sender`, the key whose coins the transaction spends;
- `inputs`, every input of the asset, as `{index, role: "user"}` or
  `{index, role: "order", terms}`;
- `outputs`, every output of the asset, as `{index, role: "change"}`,
  `{index, role: "pay", owner}`, or `{index, role: "order", terms}` with an
  `owner` when the order is another holder's.

It checks every role against the transaction before it builds anything. It
then runs the verifier locally and writes the document back with input 0's
witness in place.

## Layout

```
programs/        the SimplicityHL covenants: user.simf, verifier.simf.in (a
                 template rendered once per transaction shape), issuer.simf,
                 and contract_guarded_order.simf.in, the verifier's recogniser
                 of the guarded order, rendered in when a policy lists it
contracts/       the guarded order's descriptor, pruned programs and vectors,
                 vendored from sequentia-contracts
src/programs.rs  compiling and parameterising them; the shape menu
src/txbuild.rs   building, signing and cosigning transfers; issuer operations
src/dmt.rs       the dmt-v1 tree behind the whitelist and blacklist proofs
src/tapscript.rs the taproot construction of C_U and C_V
src/contracts.rs the templates a policy can list, the list's commitment, and
                 the guarded order's address and spends
src/bin/         the opendamp tool
tests/           builder refusals, covenant behaviour, pruning, the cosigner,
                 the snapshot format (with openampd's own documents in
                 tests/data/), the cost profile, the contract list, and the
                 two regtest proofs
vectors/         the published CMR pinning file, and contracts.json, the same
                 vectors for a policy that lists the guarded order
gomirror/        a Go mirror of the dmt-v1 tree, for the policy server
SPEC-dmt-v1.md   the tree's specification
STATUS.md        what is consensus-enforced, proven against a node
```
