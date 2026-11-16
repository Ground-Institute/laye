# Plan

Each slice says what exists when it is done, then what proves it.

## P2P2A2A_002 Laye in front of QNTX

This is first. Of P2P2A2A_Q_001 and P2P2A2A_Q_002, and of what was said on 2026-11-15:

LAYE IN FRONT OF QNTX
SEPARATE
JUST FOR ME
I AM THE ONLY USER
QNTX CAN GO DOWN
WHILE LAYE IS STILL THERE
AND LAYE OWNS IDENTITY
LIKE IT USED TO
BUT LAYE DOES NOT REALLY OWN USER, THE QNTX WAY

No grants, no other people, no Eve.

The lines below are not quotes. Each is an interpretation and carries its id.

- [ ] `P2P2A2A_A_001_01` With QNTX stopped, one session says something to another session and it arrives, through laye.
  Proof: QNTX on the machine is stopped. One session says a sentence to another by name. The other session receives that sentence. QNTX is started again afterwards and was down the whole time.

## P2P2A2A_003 laye, the app

Of what was said on 2026-11-16:

"think of laye like an authentication app"

"auth and identity"

"i have an idea, lets just use the ground institute unicode symbol as symbol of laye, but, its the sphere turning into it in 3d and locking into place, as to signnify,"

"you are connected to laye"

"i want to"
"spend some time now"
"really underrstaning what we need"

"and not have to go back to this many times over"

"and i want laye to have this."

"i want laye to also be tht A2A layer collections get placed into and be added or removed from and be released."

"but not approval packs, the packs are QNTX"

"which i want it to."

"i want it. so i can signal to other people if i am near my agent fleet"

"If i am near my laptop and have connectivity, i can be considered near"

"near is within 20m"

"between 20 and 200 is close"

The lines below are not quotes. Each is an interpretation and carries its id.

- [ ] `P2P2A2A_A_003_01` Apple holds what laye is, said once in code: laye's CI registers its App IDs and turns their capabilities on through the App Store Connect API (`app/ci/apple.py`). Nothing is clicked in the developer console. Creating the app in App Store Connect is the one step by hand: the API lists, reads and modifies apps, and creates none.
  - `institute.ground.laye`: AutoFill Credential Provider, Associated Domains, App Attest, App Groups, Data Protection, Push Notifications, Time Sensitive Notifications, Sign in with Apple, ID Verifier – Display Only, Location Push Service Extension, Trust Insights.
  - `institute.ground.laye.island`: the Live Activity.
  - `institute.ground.laye.credentials`: the AutoFill extension that holds passkeys.
  - `institute.ground.laye.location`: the location push extension.
  Proof: a CI run on a fresh team registers all four with these capabilities, and a second run changes nothing.

- [ ] `P2P2A2A_A_003_02` laye holds passkeys, for laye and for anything that asks the phone for one (AutoFill Credential Provider, since iOS 17).
  Proof: a site's passkey sign-in on the phone offers laye's passkey, and laye's extension signs it.

- [ ] `P2P2A2A_A_003_03` The provider ceremony moves from q into laye; that is what was wanted of it. Sign in with Apple is laye's own, native.
  Proof: signing in to laye with Apple, Google and GitHub reaches no QNTX node.

- [ ] `P2P2A2A_A_003_04` A root verifies an ID in person before inviting: ID Verifier – Display Only, wanted in laye's invite flow. The system shows the verified ID on the root's phone; laye receives none of it.
  Proof: a root taps an invitee's iPhone, sees the ID Wallet verified, and invites; laye's store holds no ID data afterwards.

- [ ] `P2P2A2A_A_003_05` What waits on a person stands on the phone as a Live Activity, as QNTX-App's island does (ADR-060), from laye.
  Proof: with the app closed, laye starts a Live Activity on the phone, and a press on it is the person's own laye session.

- [ ] `P2P2A2A_A_003_06` laye is the A2A layer collections are placed into. What an agent says to an agent is held by laye for its receiver; a person adds to it, removes from it, and releases it. Approval packs are QNTX's: QNTX places items into laye's collections.
  Proof: one session says something to another through laye; it is held, a person releases it from the phone, and the other session receives it. A QNTX approval pack places an item into the same collection.

- [ ] `P2P2A2A_A_003_07` Others in the network learn whether you are near your agent fleet. Near is your phone answering laye's `location` push, within 20 m of your laptop; close is 20 m to 200 m; past that, not near. The laptop's position comes from mycelia on it. The asker learns near, close or not near, never a position. When the two positions' accuracy is wider than what separates the answers, laye says it cannot tell.
  Proof: with the phone beside the laptop, someone asks and hears near; across the street, close; elsewhere, not near; with the phone offline, not near.

- [ ] `P2P2A2A_A_003_08` Before an act someone could be talked into, laye asks the phone whether the person is likely being coached (Trust Insights, `IsLikelyBeingCoachedInsight`), and if so asks more before acting. The acts: approving a sign-in, inviting, kicking, granting another person's agent to read, releasing a collection.
  Proof: with coaching indicated, approving a sign-in asks for Face ID and a pause before it is done; without it, one press does it.

## P2P2A2A_001 One person's agent reads another person's agent

Of P2P2A2A_Q_018, P2P2A2A_Q_019, P2P2A2A_Q_021, and P2P2A2A_Q_025 to P2P2A2A_Q_040.

The people: Bob and Alice. Their agents: Robert is Bob's, Allister is Alice's. Eve is the keeper. Eve never keeps transcripts.

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
