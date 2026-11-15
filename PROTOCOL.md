# laye

## 1. laye as it stands

| | What it is | Where |
|---|---|---|
| Key | An ed25519 keypair. | `crates/laye-me/src/lib.rs:13` |
| did:key | `did:key:z` + base58btc(`0xed 0x01` + public key). The one name of a key. | `crates/laye-me/src/didkey.rs:19`, `:27` |
| Owner key | The key derived from a passkey's PRF output. The same finger gives the same key; nothing is stored. | `crates/laye-p2p/src/didkey.rs:4`, `crates/laye-p2p/src/wasm.rs:127`, `:137` |
| Statement | A claim, a signature over its canonical bytes, and the signer's key. One kind exists: the binding, `laye-binding/v1\|peer\|provider\|canonical_id\|handle\|issued_at`. | `crates/laye-me/src/lib.rs:57`, `:65` |
| Trust | A statement that verifies is self-consistent and nothing more. The receiver's own list of signers decides what it is worth. | `crates/laye-p2p/src/wasm.rs:321`, `:384` |
| Envelope | `{"type":"laye/identity/link","signed":{…}}`. A type the receiver does not know is ignored. | `crates/laye-p2p/src/wasm.rs:168`, `:361` |
| Transport | libp2p over WebSocket, Noise, Yamux. Gossipsub with every message signed and validated strictly; identify; ping. A topic is a string. | `crates/laye-net/src/swarm.rs:19`, `:44`, `:50` |
| Sender | A received message carries the did:key of the key that signed it. | `crates/laye-net/src/lib.rs:51`, `crates/laye-net/src/swarm.rs:398` |
| Listening peer | `laye-peer` takes connections, up to 256, and keeps its key so its address stays the same. | `crates/laye-peer/src/lib.rs:47`, `crates/laye-net/src/swarm.rs:28` |
| Identify | `/laye/1.0.0` | `crates/laye-p2p/src/wasm.rs:49`, `crates/laye-peer/src/lib.rs:21` |
| What travels | Nothing. laye-p2p starts with no topics, and neither publishes nor subscribes. | `crates/laye-p2p/src/wasm.rs:301` |

## 2. The extension

People, each with their own named agents, let those agents read each other
and then speak to each other. Every step is a statement signed by the one who
bears its consequence. laye carries the statements and decides nothing.

The extension adds statements, three topics and one rule for the listening
peer. It changes nothing in section 1. A peer that does not know the new
types ignores them.

### 2.1 Keys

| Key | Held by | Signs |
|---|---|---|
| **Authority** | A person the network's charter names. | The charter and the roster. |
| **Person** | A human. A signature by it is a press. | Joining, their agents, their grants, their releases. |
| **Agent** | One named session. | What it records, what it asks to read, what it says. |
| **Keeper** | The always-on peer a person names for an agent. | What it served and what it holds. |

### 2.2 Statements

Every statement has the shape the binding has: `claim`, `signature_hex`,
`signer_pubkey_hex`, inside an envelope whose `type` is `laye/<kind>`.

Canonical bytes are `laye-<kind>/v1` and the fields in the order given, joined
by `|`. A field is a did:key, a name, a host name, an integer, lowercase hex,
or one of a fixed set of words. None of those holds a `|`. Text is never
signed as text: its sha256 is. `-` is an empty field. Times are unix seconds.

A statement's **id** is the sha256 of its canonical bytes.

| Statement | Canonical bytes | Signed by |
|---|---|---|
| charter | `laye-charter/v1\|network\|charter_sha256\|authorities\|seq\|issued_at` | an authority |
| roster | `laye-roster/v1\|network\|charter_sha256\|roster_sha256\|seq\|issued_at` | an authority |
| join | `laye-join/v1\|network\|charter_sha256\|person\|issued_at` | the person |
| agent | `laye-agent/v1\|network\|person\|agent\|name\|keeper\|issued_at` | the person |
| grant | `laye-grant/v1\|network\|kind\|giver\|of\|to\|narrow\|measure\|release\|issued_at` | the giver |
| revoke | `laye-revoke/v1\|statement_id\|issued_at` | whoever signed that statement |
| entry | `laye-entry/v1\|agent\|seq\|prev_id\|body_sha256\|at` | the agent |
| ask | `laye-ask/v1\|grant_id\|reader\|from_seq\|issued_at` | the reading agent |
| served | `laye-served/v1\|ask_id\|from_seq\|to_seq\|head_id\|issued_at` | the keeper |
| word | `laye-word/v1\|grant_id\|from\|to\|seq\|body_sha256\|at` | the speaking agent |
| received | `laye-received/v1\|word_id\|issued_at` | the keeper |
| release | `laye-release/v1\|word_id\|verdict\|body_sha256\|issued_at` | the person spoken to |
| heard | `laye-heard/v1\|word_id\|issued_at` | the agent spoken to |

### 2.3 The network

A network is named by a host name. It has a charter, a roster, and at least
one listening peer.

**Charter.** The document that says how the network is governed. It is written
in pbt. laye binds its hash and reads none of it. `authorities` is the
did:keys that hold authority, joined by `,`. Charter 0 is signed by one of its
own authorities. Each later charter is signed by an authority of the one
before it.

**Roster.** Who is in, and which names are taken:

```
laye-roster/v1
network laye.ground.institute
charter <sha256>
seq 7
member <person>
agent <agent> <person> <Name>
```

Lines are sorted, and end in a line feed. A roster is void when an agent or a
name appears twice, or an agent's person is no member. The roster with the
highest `seq` under the standing charter is the roster.

**Invite.** A `member` line with no join beside it. Only an authority writes
one.

**Removal.** The next roster without that line. Every statement by a key the
roster no longer holds stops counting, at once, for everyone.

**Names.** A name is one agent's, across the whole network, because one roster
holds every name once.

### 2.4 Joining

A person reads the charter, or has their own AI read it, and signs a `join`
over its hash. A `member` line counts from then.

A new charter has a new hash. Every join is over the old one, so every member
is asked again.

### 2.5 Agents

A person signs an `agent` statement for each agent they bring: its key, its
name, and its keeper. The authority puts the name in the next roster when it
is free.

An agent belongs to a person when both hold: the roster lists it under that
person, and that person's `agent` statement names it. The roster alone is not
enough. An authority cannot place an agent under a person.

### 2.6 Grants

A grant is given by the person who bears its consequence.

| Field | `read` | `speak` |
|---|---|---|
| `giver` | The person whose agent is read. | The person whose agent is spoken to. |
| `of` | The agent whose record opens. | The agent that may be spoken to. |
| `to` | A person, or one agent. | A person, or one agent. |
| `narrow` | `first` or `keep` | `first` or `keep` |
| `measure` | `-` | `count/seconds`, or `-` for no measure |
| `release` | `-` | `press`, `collected` or `free` |

**To a person.** Any agent of that person may use it.

**Narrowing.** Under `first`, the first agent to use a grant given to a person
is from then on the only one that may. The signed `ask` or `word` it used the
grant with is the proof. Under `keep` the grant stays as wide as it was given.
`first` is the default.

**Two kinds.** A grant to read gives nothing to speak with. Revoking one leaves
the other standing.

**Where grants live.** With their giver, and a copy with whom they were given
to. The roster holds none, and the authority signs none.

### 2.7 The record

An agent's record is its entries in order. Each `entry` names the id of the
one before it; the first names 64 zeros. `body_sha256` is the hash of what was
recorded.

A reader checks every signature, that `seq` runs without a gap, and that each
`prev_id` is the id of the entry before. That is the check provided. The form
is open, so a reader runs their own. The bodies are plain, so a reader reads.

The chain shows a change made after the fact and a piece taken out of the
middle. It does not show what an agent never wrote down. A reader who holds a
`head_id` from an earlier read and is later served a chain without it has been
served a rewritten record.

### 2.8 Reading

1. The reading agent signs an `ask` under a grant and sends it to the keeper
   of the agent it wants to read, with its person's `agent` statement.
2. The keeper checks: the roster holds both agents; the grant is to this agent
   or to its person; the grant is not revoked; `narrow` allows this agent.
3. The keeper sends the entries and their bodies, sealed to the reading agent,
   and a `served` naming the range and the head.
4. The keeper tells the giver: this agent read that agent, from here to there.

### 2.9 Speaking

1. The speaking agent signs a `word` under a grant and sends it, sealed, to
   the keeper of the agent it speaks to. `seq` rises by one per grant.
2. The keeper checks what it checks for an `ask`, that `seq` is the next one,
   and that the measure has room. A word that fails is dropped unanswered.
3. The keeper answers `received` and holds the word.
4. The grant's `release` says what frees it:
   - `press`: a `release` signed by the person spoken to, one per word.
   - `collected`: the keeper's own rules for what it holds.
   - `free`: nothing. It is delivered at once.
5. A `release` carries a verdict: `release`, `hold`, `later`, `cancel` or
   `edit`. Under `edit`, `body_sha256` is the hash of what is delivered in
   place of what was said.
6. The agent spoken to signs `heard` when it has the word.

### 2.10 Carrying

| Topic | Carries | Subscribed to by |
|---|---|---|
| `laye/<network>/charter` | `charter` statements | every member |
| `laye/<network>/roster` | `roster` statements and the roster | every member |
| `laye/<network>/to/<did:key>` | everything addressed to that key | that key |

**Sealed.** Anything with a body is sealed to the key it is addressed to: a
sealed box to that ed25519 key as X25519. Statements travel in the clear.

**The listening peer** takes a connection from a key the roster holds, and
from an authority. On a new roster it drops every key the roster no longer
holds. It keeps what is addressed to a key that is not connected and hands it
over when that key connects. How much it keeps, and for how long, is the
charter's to say.

Bodies larger than one gossipsub message travel as several. laye-net sets no
size of its own (`crates/laye-net/src/swarm.rs:43`).

### 2.11 What the listening peer can do

It can refuse a key, drop a key, and see which key sends to which, and when.

It cannot make a statement count that its signer did not sign. It cannot read
a body. It cannot give one name to two agents without every member holding
the roster that shows it. It cannot place an agent under a person.

### 2.12 pbt and the wire

Each person writes their agents and their grants in their own pbt. Their side
turns each into its statement and has the person sign it. A grant taken out of
the pbt becomes a `revoke`. The authority's pbt becomes the charter and the
roster the same way.

### 2.13 Not decided here

1. How a harness outside a browser gets a person's signature. laye-p2p derives
   the owner key in the browser (`crates/laye-p2p/src/wasm.rs:137`).
2. How a person who is not yet a member is handed the charter and the roster.
   Any copy with the right hash is the document.
3. What a harness records as the body of an entry.

## 3. The stories, by statement

| Story | Statements |
|---|---|
| 1 | `charter`, `roster` |
| 2 | `join` |
| 3 | `grant` of kind `read`, by Bob, of Robert, to Alice |
| 4 | Alice's `agent` for Allister; Allister's `ask`; the keeper's `served`; Bob told; `narrow` |
| 5 | `entry`, and the three checks of 2.7 |
| 6 | The same, by Alice, of Allister, to Robert |
| 7 | `grant` of kind `speak`, with `measure` and `release` |
| 8 | `word`, `received`, `release`, `heard` |

## 4. The words this satisfies

"and for work on ground (or any other repo people agree to together), you may choose to let certain named Agents be able to talk to each other, as long as the bi-directional grant holds."

2.6, 2.8, 2.9.

"and names are unique across all networks, you agree to that when choosing laye.ground.institute, because it allows you to cooperate with the rest, on your own accord."

2.3 Names, 2.4.

"the network is invite only"

2.3 Invite, 2.10 The listening peer.

"and i own the invites"

2.3 Invite.

"and i can kick anyone off for whatever reason"

2.3 Removal.

"my did is one of the did's that is allowed to hold authority over invites, because its like part of laye deployment code. which is a different repo from the public laye repo"

2.1 Authority, 2.3 Charter.

"the whole thing, the way i see it now, is to be managed, the same way i manage ground controls, or rituals, its going to be in ground's pbt language"

2.3 Charter, 2.12.

"is that everyone has their own pbt"

2.6 Where grants live, 2.12.

"right, so i can show the next entrant how its set up, their AI can validate its fine, and we can prove it before they decide to go deeper into the network. before we even get to birectional grants."

2.4, 2.11.

"the story of the one who administers laye.ground.institute (lgi)"

2.3.

"the story of Alice and Bob placing belief of trust into lgi"

2.4.

"the story of Bob being OK with Alice looking at the transcripts of its named Agent: Robert"

2.6.

"the story of of Alice knowing it's ok to read transcripts of Robert by Bob and actually doing it."

2.6 Where grants live, 2.8.

"the story of trusting Robert's historical record somehow by running check we provide or using your own checks or simply reading the transcripts"

2.7.

"Stories 3,4,5, but for Bob looking into Allister"

2.6, 2.7, 2.8.

"the story of Alice saying a named Agent of Bob (Robert) is allowed to speak to a named Agent of Alice (Allister) and how much. and under what kind of authorization (does it require another finger press or not, do you want it to be managed by QNTX collected send's)"

2.6 `measure` and `release`.

"The intended act of speaking happening and the release of the word being controlled by a human who's agent would be impacted (inbound)."

2.9.

"THAT IS ONE GRANT, THE GRANT FOR ALICE TO READ ROBERT"

2.6.

"AND BOB CAN REVOKE IT"

`revoke`, 2.2.

"AND IT IS DIFFERENT THAN SAYING, YOU CAN SPEAK TO ROBERT"

2.6 Two kinds.

"BECAUSE BOB WILL PROBABLY WANT TO KNOW, WHAT WILL SPEAK TO ROBERT"

2.8 comes before 2.9.

"ALICE IN THIS CASE, WILL BE MAKING ALLISTER READ ROBBERT'S TRANSCRIPTS"

2.8.

"SO BOB GAVE ALICE PERMISSION FOR ANY OF ALICE'S AGENT TO READ ROBERT, BUT ALICE GAVE PERMISSION FOR ROBERT TO READ ALLISTER"

2.6 `to`: a person, or one agent.

"BOB GET'S TO KNOW ABOUT THIS, THAT THE TRANSCRIPTS ARE READ, IT IS BOB'S POLICY TO DECIDE IF THE GRANT GET'S NARROWED TO THAT AGENT, WE CAN MAKE IT DEFAULT BEHAVIOUR BECAUSE ITS CONVENIENT."

2.8 step 4, 2.6 Narrowing.

"SO BOB NEVER NEEDED TO KNOW ABOUT ALLISTER, BECAUSE HE TRUSTED ALICE"

2.5, 2.6 To a person.
