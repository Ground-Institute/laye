# Plan

Each slice says what exists when it is done, then what proves it.

The people: Bob and Alice. Their agents: Robert is Bob's, Allister is Alice's. Eve is the program that holds Robert's transcripts for Bob and answers requests to read them.

## P2P2A2A_001 One person's agent reads another person's agent

Of P2P2A2A_Q_018, P2P2A2A_Q_019, P2P2A2A_Q_021, and P2P2A2A_Q_025 to P2P2A2A_Q_040.

- [x] `P2P2A2A_001.1` Bob grants Alice to read Robert. Alice authorizes Allister to use that grant. Allister asks Eve. Eve serves or refuses, and after the first read the grant is narrowed to Allister.
  Proof: `alice_has_allister_read_robert`, and eleven beside it. `9d2647a`.

- [ ] `P2P2A2A_001.3` Only Alice can authorize her agent, and only Bob can grant.
  Alice's authorization is the `Authorization` message in the proto: it names Bob's grant and names Allister, and Alice signs it.
  Now: in the tests Alice's key is a key in memory. If it were a file on her laptop, Allister has a shell there, could read it, and could sign as Alice.
  When done: Alice signs by pressing her finger on a page that shows what she is authorizing. The key that signs is the one QNTX already derives from a passkey press. It exists during the press and is stored nowhere. Bob gives a grant the same way, and either takes theirs back the same way.
  Proof: Alice presses, and Eve serves Allister. Allister signs an authorization itself with every key it finds on the laptop, and Eve refuses each one.

- [ ] `P2P2A2A_001.4` Eve serves Robert's real transcripts.
  Now: Eve serves three rows typed into the test file.
  Where Robert's transcripts are depends on Bob. Claude Code always keeps its own file, and ground adds two more places. That gives three cases, and each gives a different level of guarantee:
  1. Bob never used ground. Only Claude Code's own file has them, one file per session, under `~/.claude/projects/`.
  2. Bob uses ground since some time. From that time on, ground's local store has them too, written by ground as it happened. Before that time, only case 1.
  3. Bob uses ground on the ground namespace. From then on his node has them too. The namespace gives temporal guarantees.
  An agent's traces can also be somewhere else entirely, not in ground or QNTX: OTel logs, Sentry, the LangChain ecosystem.
  When done: Eve reads through one opening that any such place can sit behind. The three cases above are the first ones built. With every answer Eve says which place it came from.
  Proof, for each place built: on Bob's machine a command prints the hash of Robert's transcripts on teranos/ground, taken straight from that place. Allister asks Eve. The hash Eve signs is the same, the hash Allister computes over what arrived is the same, and the answer names the place. Allister then asks about a repository Robert never worked in and gets nothing.

- [ ] `P2P2A2A_001.5` It travels between machines.
  Now: the grant, the authorization, the request and the answer are passed inside one test process.
  When done: they go over laye, encrypted so that only the one they are for can read them.
  Proof: Allister on one peer and Eve on another, connected only through a third. The third carries it and cannot read it.

- [ ] `P2P2A2A_001.6` Bob is told that Robert was read, and by which agent (P2P2A2A_Q_039).
  Proof: Bob's session shows that Allister read Robert.

- [ ] `P2P2A2A_001.7` The other direction (P2P2A2A_Q_037): Alice grants Robert to read Allister.
  Proof: with Alice on l and Bob on k, Allister reads Robert and Robert reads Allister.
