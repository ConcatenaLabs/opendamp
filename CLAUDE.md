# OpenDAMP

Network enforcement for a regulated asset on Sequentia. The asset's policy is
enforced by Simplicity covenants that every node runs, with no server in the
path of a transfer. This repository holds the covenant programs
(`programs/*.simf`), the Rust library that builds and signs transfers under
them, the `opendamp` command-line tool, and the CMR pinning file
(`vectors/addresses.json`).

`README.md` covers the tool, `STATUS.md` records what is and is not enforced by
consensus and how each claim is proved, and `SPEC-dmt-v1.md` is the frozen tree
format. Read `STATUS.md` before describing a policy to anyone. `DESIGN.md` is the
protocol. The node and consensus conventions are in the
[`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) repository.

The policy service that publishes snapshots and issues network-enforced assets
is `openampd`, in the [`openamp`](https://github.com/ConcatenaLabs/openamp)
repository. It mirrors parts of this crate in Go and pins a copy of
`vectors/addresses.json` in its tests.

## Build and test

```sh
cargo build --release
cargo test
cargo test --test regtest -- --ignored --nocapture   # needs a node and the token-covenants tool, see README
cargo test --test regtest_contracts -- --ignored --nocapture   # needs a node: the asset in an order
```

There is no CI. `cargo test` and the regtest proof before every PR that touches
a program or the transaction builder are the whole gate.

## Things that are expensive to get wrong

- **A program change changes every address.** The CMRs in
  `vectors/addresses.json` are what wallets and `openampd` verify programs
  against, and an asset already issued is bound to its programs for life. When
  a change to `programs/` or `src/tapscript.rs` is intended, regenerate the
  vectors, then update the Go mirrors in `openamp` (`openampd/internal/damp/`,
  `openampd/internal/elements/simplicity.go`) and its pinned copy of the
  vectors in the same sitting.
- **The covenants need the four-per-byte Simplicity budget**
  (`SIMPLICITY_BUDGET_PER_WITNESS_BYTE` in the node's `src/script/script.h`). On
  a node without it they are unspendable by design.
- **`q` units of the verifier asset must never exist outside a verifier
  covenant.** No covenant of the asset can check this (`STATUS.md` explains
  why); a halt burns the verifier to `OP_RETURN` and records it in the
  verifier asset's token covenant (`sequentia/verifier-token`, in
  sequentia-contracts), the only place that token may live, which mints the
  verifier amount back only into a recorded verifier. Never move that token
  into a wallet.
- **A policy that lists no contract template renders its verifier exactly as
  before.** The recognisers are rendered in only for a listed template, and
  the list commits in `rules_root`'s fourth slot, which is zero for none.
  Regenerating `vectors/addresses.json` from `examples/snapshot-seq0.json` must
  give the file byte for byte; if it does not, every live asset's verifier
  address has moved.
- **A contract template joins `contracts::WHITELISTABLE` only with a guard
  and an owner term.** Every spending path must refuse a transaction without
  q of V at input 0, and the template must name its owner, so that the
  verifier is in every transaction that moves the contract's coin. A template
  without the guard lets the asset leave it unpoliced. `contracts/` vendors the
  template's descriptor, pruned programs and vectors from sequentia-contracts,
  and `tests/contracts.rs` pins the constants in `src/contracts.rs` to them.
  The template is immutable: a change there is a new template, and so a new
  entry here.
- **dmt-v1 guards hash under domain `0x03`**, never as key leaves; `recv_after`
  never binds the sender's own change; `pi` is a compile-time parameter that
  reaches the program. Each of these was once wrong; `STATUS.md` section 0 has
  the detail.

## Working in this repo

- PRs go against `main`, which is the remote default.
- The repository is public. Issuer keys, holder keys and request files that
  carry private keys never belong in it; `examples/` holds only test material.

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as the person the session is working for.** Several people
commit in these repositories and an agent always runs on behalf of one of them,
so derive the author from the authenticated GitHub account rather than from a
list of names that goes stale the moment somebody new arrives:

    git -c user.name="$(gh api user --jq '.name // .login')" \
        -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
        commit ...

That address is the GitHub `noreply` form, which is what links a commit to its
account and keeps private addresses out of a public history. When `gh` is not
authenticated as the person the work belongs to, ask them instead of guessing.

**Never infer the author from `git log`.** The clones carry no `user.name` or
`user.email`, so `git commit` stops with "Author identity unknown" and the
nearest answer to hand is the author of the last commit — which is whoever
pushed last and says nothing about who is working now. Attributing a commit to
someone who did not write it puts their name on code they never reviewed, and
taking it back costs a history rewrite and a force-push over commits other
machines have already pulled.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Documentation is part of the change, not a follow-up.** A change that makes a
README, a doc page, a runbook or a code comment wrong is not finished until that
text is right again, in the same pull request as the code. Before you open the
pull request, search the repository for whatever you renamed, moved or removed —
the old binary name, the old path, the old flag, the old command — and fix every
hit. If the change falsifies another repository's documentation, that repository
gets its own pull request in the same sitting. A stale instruction costs a new
user more than a missing one: they trust it, run it, it fails, and the failure
reads as broken software rather than as an out-of-date sentence.

**Write documentation to be timeless.** Assume the reader is new, arrived today,
and wants to know what the software is and how to use it right now. They do not
care what changed, what it used to be called, or which version added what. So
write in the present tense about current behaviour, and leave the history out:
no changelogs, no "new in", no "recently", no "coming soon", no status or
progress sections, no roadmaps, no dated notes. Quote a version number only where
the reader cannot act without it, and prefer pointing at the file that carries it
over copying the digits. Timeless does not mean thin — what the product is, who
it is for, and how to install, configure and use it all still belong there, in
full. Documentation written this way survives a release without an edit, which is
what keeps it true; the history already has homes in the git log, the tags and
the release notes.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
