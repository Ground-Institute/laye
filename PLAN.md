# Plan

Each slice says what exists when it is done, then what proves it.

The people: Bob and Alice. Their agents: Robert is Bob's, Allister is Alice's. Eve is the program that holds Robert's transcripts for Bob and answers requests to read them.

## P2P2A2A_001 One person's agent reads another person's agent

Of P2P2A2A_Q_018, P2P2A2A_Q_019, P2P2A2A_Q_021, and P2P2A2A_Q_025 to P2P2A2A_Q_040.

- [x] `P2P2A2A_001.1` Bob grants Alice to read Robert. Alice authorizes Allister to use that grant. Allister asks Eve. Eve serves or refuses, and after the first read the grant is only Allister's.
  Proof: `alice_has_allister_read_robert`, and eleven beside it. `9d2647a`.

- [ ] `P2P2A2A_001.3` Only Alice can authorize her agent, and only Bob can grant.
  Alice's authorization is the `Hand` message in the proto: it names Bob's grant and names Allister, and Alice signs it.
  Now: in the tests Alice's key is a key in memory. If it were a file on her laptop, Allister has a shell there, could read it, and could sign as Alice.
  When done: Alice signs by pressing her finger on a page that shows what she is authorizing. The key that signs is the one QNTX already derives from a passkey press. It exists during the press and is stored nowhere. Bob gives a grant the same way, and either takes theirs back the same way.
  Proof: Alice presses, and Eve serves Allister. Allister signs an authorization itself with every key it finds on the laptop, and Eve refuses each one.

- [ ] `P2P2A2A_001.4` Eve serves Robert's real transcripts.
  Now: in the tests the transcript is three rows written in the test.
  When done: Eve reads what Robert said on one repository, in order, from where Bob keeps it.
  Proof: Allister receives Robert's transcripts on teranos/ground, and nothing of Robert's from another repository.

- [ ] `P2P2A2A_001.5` It travels between machines.
  Now: the grant, the authorization, the request and the answer are passed inside one test process.
  When done: they go over laye, encrypted so that only the one they are for can read them.
  Proof: Allister on one peer and Eve on another, connected only through a third. The third carries it and cannot read it.

- [ ] `P2P2A2A_001.6` Bob is told that Robert was read, and by which agent (P2P2A2A_Q_039).
  Proof: Bob's session shows that Allister read Robert.

- [ ] `P2P2A2A_001.7` The other direction (P2P2A2A_Q_037): Alice grants Robert to read Allister.
  Proof: with Alice on l and Bob on k, Allister reads Robert and Robert reads Allister.
