# Plan

「[Fable 5.2] Written 2026-11-15. The one place the work is tracked (Q46). It repeats neither the owner's words, which are in [QUOTES.md](QUOTES.md), nor the contract, which is [proto/laye/v1/laye.proto](proto/laye/v1/laye.proto): it names both. Every box is open until its proof exists. *Stands* holds only what was read in code that day; *Not read* is said where it was not.」

## Three files, and no fourth

| File | Holds | Never holds |
|---|---|---|
| `QUOTES.md` | The owner's words, numbered (Q42, Q45) | Anyone else's |
| `proto/laye/v1/laye.proto` | What is on the wire (Q44) | Reasons, plans |
| `PLAN.md` | What is missing, as boxes, by track (Q46, Q48, Q52) | A rewording of either |

A fourth document is a second source of truth (Q47). What would go in one goes in one of these.

## The one thing

The carve-out (Q25 to Q40, Q50) is the contract. It is settled when the owner has read `laye.proto` and merged it. Everything below builds on it and changes none of it.

## Tracks

Each track can be worked alone (Q51, Q52). A track's proof is the one thing that, once it passes, makes its part true.

### A. The contract

Stands: `laye.proto` compiles (`protoc`, 2026-11-15). No code reads it.

Decided in it beyond the owner's words, each to keep or strike:

- [ ] **Hand.** An agent uses a person's grant only when the person hands it over, by signature, per grant.
- [ ] **about.** A grant is about one repository (Q5), not all an agent ever did.
- [ ] **opens.** A grant opens a provider's checks only, or the record too (Q20).
- [ ] **until.** A grant, a hand and an entrustment can end on their own.
- [ ] **State and Stands.** The keeper says what a grant is now, signed, to both sides.
- [ ] **Refused and Why.** A refusal says which thing failed.
- [ ] **Sealed.** Everything in transit is sealed to the key it is for, statements too.
- [ ] **Entrust and Check.** A provider is named by the person, and its findings are its own.

Then:

- [ ] laye builds its types from `laye.proto`.
- [ ] A statement is signed and verified over the bytes carried, as `Statement` says.

Proof: a test that builds the whole chain, Grant, Hand, Ask, Served, Stands, and verifies it from the links alone.

### B. A person's signature

Everything rests here. A Grant, a Hand, a Revoke and an Entrust are a person's. An agent runs as its person's user on its person's machine, and reads what that user reads. A person's key kept in a file is every agent's key.

Stands: laye-p2p derives a key from a passkey's PRF output in the browser, and signs with it (`crates/laye-p2p/src/didkey.rs:4`, `crates/laye-p2p/src/wasm.rs:127`, `:137`). ground carries a person's presses to the node through mycelia (`ug/mycelia.d`, `pressAllowed`, in teranos/ground).

Not read: QNTX ADR-060, `server/auth/homeward.go`.

- [ ] Where a person signs a statement: a page that derives the owner key and signs the bytes shown.
- [ ] What is shown before the finger: the statement in words, not its bytes.
- [ ] A session asks for a signature and waits; it never holds what makes one.
- [ ] Whether a person signs with the node down (Q1).

Proof: an agent on the same machine, with shell, cannot produce a Hand for itself.

### C. The keeper

Each person keeps their own agents' records and answers for them (Q59, Q60, Q61).

Stands: ground writes a row for each hook event, and they reach the `ground` namespace of the owner's node k. QNTX-Quotes reads them there by predicate: `UserPromptSubmit`, `PostToolUse`, `Stop`, `SessionStart`, each with its session and `project:owner/repo` (`reading.go`, in sbvh-nl/QNTX-Quotes).

Not read: how a row is signed and by which key; QNTX's `transcripts_read`.

- [ ] A position: a stable order of one agent's rows on one repository, for `after` and `upto`.
- [ ] A body: what of a row is sent. What is left out, and who decides.
- [ ] The keeper: verifies the chain, holds each grant's State, answers Served or Refused, says Stands.
- [ ] The giver is told of each Served (Q39).
- [ ] Where it runs: in the node, or beside ground on each machine (Q1, Q2).

Runs into: **reading cannot be taken back.** A revoke stops the next Ask, not what was already sent. And a record holds everything the agent saw: code, pasted secrets, other people's words. `about` and `opens` are the only bounds on that, so what a body leaves out matters more than anything else in this track.

Runs into: **a record read by an agent is input to that agent.** Robert's past, including every page and tool result Robert ever took in, reaches Allister with no hand on it. Story 8 guards a word; nothing yet guards ten thousand rows. The reader's side takes a record in as data.

Proof: one agent asks another person's keeper under a grant and is served; an agent that was not handed the grant is refused with `NOT_HANDED`.

### D. Carrying

Stands: laye-net carries signed gossipsub messages between peers; `laye-peer` takes connections; one message has gone from one peer to another through a third, with its sender as a did:key (`crates/laye-peer/tests/through_a_peer.rs`). Nothing else publishes: laye-p2p starts with no topic (`crates/laye-p2p/src/wasm.rs:301`).

- [ ] A Parcel on `laye/to/<did:key>`: sealed to its key, opened by it.
- [ ] A laye peer on each machine that runs a harness (Q2). mycelia is D; the peer runs beside it.
- [ ] What holds a Parcel for a key that is not connected, and for how long.
- [ ] A body larger than one message.
- [ ] `laye.ground.institute` resolves (the owner's, at the registrar).
- [ ] A `laye-peer` runs behind it.
- [ ] QNTX-Web's `ts/laye.ts` names `relaye.sbvh.nl`, which is dead.

Proof: a session on one machine says a word to a session on another while the node is down (Q1).

### E. pbt

A person's grants are written in their own pbt (Q12, Q13).

Stands: ground's `parseOrg` takes `github`, `actions_minutes` and one `sentry { }` block, and refuses any other key (`source/proto.d:1405`, in teranos/ground).

- [ ] How a Grant, a Hand and an Entrust are written in pbt.
- [ ] `org { }` grows (Q15).
- [ ] From pbt to statements: what is written and not yet signed is shown to the person, who signs.

Runs into: **an agent can edit a pbt.** So the pbt cannot be what gives. It is the plan; the signature is the act. A grant in the pbt with no signature is a draft, and a signed grant no longer in the pbt is to be revoked: a person reconciles the two with a finger, as `make apply` reconciles a plan.

Proof: an agent adds a grant to its person's pbt, and nothing is given.

### F. Trust providers

A third party the person lets check their agent's record (Q53, Q54, Q55, Q61).

Stands: QNTX-Quotes measures, mechanically, whether what an agent put in double quotes was said by a person (`quote/watch.go`, `quote/policy.go`), tells a person when a commit removed their words (`quote/removal.go`), and puts what an agent wrote inside the agent's own quotation, by session and model (`quote/landed.go`). It is compiled into k alone, and its one sigil is `of ROOT SUPER` (`reach`).

Not read: `reads/demand.go`, `crates/quotes-wasm`.

- [ ] How the rows of an agent reach a provider its person entrusted it to, and that the provider need not keep them (Q60).
- [ ] QNTX-Quotes answers as a Check: its measures over a named stretch.
- [ ] A method has a name and a version; its numbers stay the provider's (`quote/policy.go` asks to be moved already).
- [ ] QNTX-Quotes checks the record of someone who is not ROOT on its node.
- [ ] How a provider is paid (Q55).
- [ ] How someone runs their own (Q55).

Runs into: **what Quotes measures is the one risk the carve-out leaves open.** Bob trusts Alice, not Allister (Q40). That is sound only when Allister is faithful to Alice: says of her only what she said, and passes none of its own writing off as hers. That fidelity is what Quotes measures. A provider is not an extra on the carve-out; it is what makes trusting the person enough.

Runs into: **a provider is a witness, if it is shown each row as it happens.** A record only its owner has seen can be written again before anyone looks. A provider that keeps the digest of what it was shown, and when, makes that visible, and needs to keep none of the record to do it. A provider one runs oneself gives the checks and a weaker witness.

Runs into: **checks compare only when they are of the same thing.** `Check` names its stretch by position and digest so two providers' takes on one record can be set side by side. That needs track C's positions.

Proof: Alice is served a Check of Robert signed by a provider on her own list, and none of Robert's record.

### G. lgi, the network

Names, invites, removal, and how the institute is governed (Q6 to Q11, Q14, Q16, Q17).

Stands: `laye-peer` admits any key, up to 256. Session names are taken at the owner's node q, which holds a name to a form.

Not read: how q keeps names, and to whom a name is unique.

Draft, not carried into the contract: charter, roster and join, in this repository's history at `2b4edc5`, `PROTOCOL.md` 2.3 to 2.5.

- [ ] The charter and the roster, in the contract.
- [ ] One registry of names: lgi's, or q's, and not both (Q6, Q47).
- [ ] `laye-peer` admits only whom the roster holds (Q8).
- [ ] Removal reaches every keeper (Q10).
- [ ] What an entrant is shown before joining, and what their AI can check of it (Q14).

Runs into: **the carve-out needs none of this.** Two people with keys can do all of track A without a network. lgi adds names people can say, and a door. That is why it can come after.

Proof: a key the roster does not hold is refused at the door; a key removed from it is dropped.

### H. Namespaces

A GitHub organisation mapped to a namespace its administrators own (Q56, Q57). The institute's lives on q and holds no one's transcripts (Q58, Q60).

Stands: the node's GitHub App is installed on `teranos` and `sbvh-nl` (`vault owners`, 2026-11-15).

Not read: QNTX's namespaces, ADR-046.

- [ ] A namespace owned by its administrators, not by ROOT.
- [ ] A GitHub organisation mapped to one namespace.
- [ ] The `ground-institute` namespace on q.
- [ ] The App installed on `Ground-Institute` (the owner's).
- [ ] This repository bound whole into the vault (Q43), so these three files are read and ticked there.

### I. Speaking

A grant of its own (Q22, Q23, Q32, Q33). Kind 2 is kept for it.

Not read: QNTX's collected sends and A2A.

Draft, not carried into the contract: word, received, release and heard, in this repository's history at `2b4edc5`, `PROTOCOL.md` 2.9.

- [ ] The grant to speak: how much, and what frees a word (Q22).
- [ ] The word, held, and released by the person spoken to (Q23).
- [ ] One carrier for a word between two agents: QNTX's or laye's, not both (Q47).

Runs into: **a word to an agent is a prompt.** The release is a person reading an instruction to their own agent before it lands.

Runs into: **two agents free to speak both ways are a loop with no person in it,** spending both people's usage. The measure is the only brake, so a grant to speak with no measure admits no word.

### J. Asking

Nothing in the stories tells Bob that Alice wants a grant. The first move is outside the contract.

- [ ] Whether asking for a grant is a statement, or stays between people.

## Loose ends

- [ ] laye's code is in two places: `crates/laye-*` on teranos/QNTX#1753, and here. QNTX takes laye from here, and its copy goes (Q47).
- [ ] teranos/QNTX-Web#135 is a draft, waiting on a QNTX release that carries #1753.
- [ ] The note `Ground/Ground Institute.md` in the vault holds Q1 to Q41 a second time. It goes when this repository is bound into the vault (track H).
- [ ] `Ground-Institute/laye.ground.institute` is empty, and holds nothing until it holds lgi's own pbt.
