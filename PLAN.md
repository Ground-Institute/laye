# Plan

Each slice says what exists when it is done, then what proves it.

## P2P2A2A_005 C holds laye's name

Owner: Fuck.

Of what was said on 2026-11-26:

"that laye itself laye ground institue itself has its own pbt governing itself, and you can see it on github, and that is what verified means"

"laye owns identity, laye owns login, laye owns A2A"

"why does it point to a specific qntx backend"

"laye needs to keep being there when qntx is down"

"ok, so i want C to be the one"

The lines below are not quotes. Each is an interpretation and carries its id.

- [x] `P2P2A2A_A_005_01` C says who administers laye.ground.institute, as the pbt it is deployed with says (Ground-Institute/laye.ground.institute `controls/laye.pbt`), and nothing else about anyone.
  Proof: on 2026-11-26 08:29 UTC `https://c.sbvh.nl/laye/administrator/teranos` answered `{"administers":true,"administrator":"teranos"}` and `/laye/administrator/nobody` answered `{"administers":false,"administrator":"nobody"}`.

- [ ] `P2P2A2A_A_005_02` At laye's own name C stands in front: it answers what it holds, and hands every other request on to laye's front on q, as it came.
  Proof: with laye.ground.institute reaching C, a passkey signs a person in there as before, and `/laye/administrator/teranos` there is C's answer.

- [ ] `P2P2A2A_A_005_03` laye.ground.institute reaches C. Until now the name was a record pointing at q, made on 2026-11-15 when laye ran nowhere else.
  Proof: the name resolves through Cloudflare, and `ground laye` hears laye's yes.

- [ ] `P2P2A2A_A_005_04` What laye's front holds moves into C, piece by piece: people and their passkeys, login, the ceremony (`_003_03`), what is collected (`_003_06`). They are kept in the etcd q, k and l share, which C does not reach.
  Proof: with q stopped, a person signs in at laye.ground.institute and one session says something to another.

- [ ] `P2P2A2A_A_005_05` C has one deployer: Ground-Institute/laye.ground.institute, on a push to main. laye's `c-stack` deploys it no longer.
  Proof: a push to `c-stack` deploys nothing, and C's running version is main's.

## P2P2A2A_004 Every collection waiting on a person, in one place

Owner: Cumulus.

Of what was said on 2026-11-22:

"i see, so it's workable now, but isn't spectacular to demo or be a daily driver, this is very much an early prototype of the core idea."

"well, i see the lampligher one on my phone, but appareantly i cant delay it? or i get no feedback on it?"

"another issue is, that when i press it, it doesnt make me go to the actual collection, which is a real ux error"

"it would be cool right? the combination of ag and the live activity seems powerful."

"but what i also miss is, seeing the ones that are here right now, on my own machine, why those dont show up in the live activity."

"what if i could have an interface, where i see all collections waiting for me, so not just one."

"like a place where i can interact per collection, and move things around so i can set the chronological order, or exact timing if i want."

"yeah, this is what needs to be happening anyways."

"mycelia jusk asked for my finger twice in a row"

"YOU, not me, but YOU, its DECIDED, WE WANT THIS"

"but why am i not the one to admit, through ag ?"

"ok, just note it, and do it manuyally for now, but what we want of course is for ag to be handling these kinds of session specific things."

The lines below are not quotes. Each is an interpretation and carries its id.

- [x] `P2P2A2A_A_004_01` What is collected reaches the person as it changes, not on the next time they ask.
  Proof: laye#22 (on q since 2026-11-22 08:33:51 UTC) and mycelia#3. A `ground say` at 09:35:18 was in mycelia's `collected`, which ag draws, at 09:35:19.

- [ ] `P2P2A2A_A_004_02` One collection: what a node collects for an agent is placed into laye, as `_003_06` says. QNTX keeps none of its own (`server/collected.go`); a GitHub or room wake for an agent is collected at laye like anything an agent says.
  Proof: a merge GitHub tells Lamplighter of stands in ag and at `/laye/collected`; QNTX's `collected list` is empty.

- [ ] `P2P2A2A_A_004_03` Each thing said has its own time and its own place in the order. What waits for an agent is no longer one due for all of it: the person moves one before another, or sets one to a moment, and it is delivered then, in that order.
  Proof: three things wait for one agent; the person puts the last first and sets one to 14:00; the agent receives them in that order, the one set at 14:00.

- [ ] `P2P2A2A_A_004_04` One page with every collection waiting on the person, at laye: each agent's, what it holds, and every act on it (release, hold, later, cancel, edit, move, set a time), held up to date by `/laye/collected/watch`.
  Proof: with things waiting for three agents, the page shows all three; an act on one shows on the page, in ag and on the phone within seconds.

- [ ] `P2P2A2A_A_004_05` The phone reads laye: the Live Activity stands for what waits at laye, the ones from this machine too. A tap opens that collection on the page. A delay shows until when before it leaves.
  Proof: a `ground say` on l stands on the phone; tapping it opens its collection; delaying it shows its new time and the node holds it until then.

- [ ] `P2P2A2A_A_004_06` A mycelia restart costs no finger: what ag was paired with outlives mycelia, and is still given to nothing but a press in ag.
  Proof: mycelia is installed again; the next press in each session's ag asks no finger; a process that is not ag asking mycelia's socket is still refused.

- [ ] `P2P2A2A_A_004_07` What is particular to one session is the person's to do in ag, in their session: admitting an agent laye does not know is one. A release to an agent not admitted at laye shows on its line in ag as a press to admit it; the press admits it in the person's session, and the release goes on. A key admits sessions as ground does now, and is never the only way.
  Proof: a session whose key laye has not admitted is said to; releasing it in ag offers to admit it; one press admits it and the other session receives what was said. On 2026-11-22 Window was admitted by hand instead (`/auth/admit` signed by the key the person said yes to), because there was no such press.

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

"i think that the magic island should in a sense be responsibility of laye"

"well, like, even collections and the idea of approval packs, it would also move to laye"

"i really like having the island be available to both the existing QNTX App and laye now as well,"

"i feel like there is a good argument to put the island into its own repo, and a generalised thing all other projects of mine use that would be using it,"

"and the same really goes for everything else that laye app would be using from QNTX-App"

"it means the agents, interacting with them"

"it needs to move to laye as well"

"so laye would not be owning llm gateway type stuff or other of that kind of automation i guess"

"hm... i guess QNTX hosts them, but isnt exclusive host"

The lines below are not quotes. Each is an interpretation and carries its id.

- [ ] `P2P2A2A_A_003_01` Apple holds what laye is, said once in code: laye's CI registers its App IDs and turns their capabilities on through the App Store Connect API (teranos/ios-common `apple/apple.py`, reading `app/apple.json`). Nothing is clicked in the developer console. Creating the app in App Store Connect is the one step by hand: the API lists, reads and modifies apps, and creates none.
  - `laye.ground.institute`: AutoFill Credential Provider, Associated Domains, App Attest, App Groups, Data Protection, Push Notifications, Time Sensitive Notifications, Sign in with Apple, ID Verifier – Display Only, Location Push Service Extension, Trust Insights.
  - `laye.ground.institute.island`: the Live Activity.
  - `laye.ground.institute.credentials`: the AutoFill extension that holds passkeys.
  - `laye.ground.institute.location`: the location push extension.
  Proof: a CI run on a fresh team registers all four with these capabilities, and a second run changes nothing.

- [ ] `P2P2A2A_A_003_02` laye holds passkeys, for laye and for anything that asks the phone for one (AutoFill Credential Provider, since iOS 17).
  Proof: a site's passkey sign-in on the phone offers laye's passkey, and laye's extension signs it.

- [ ] `P2P2A2A_A_003_03` The provider ceremony moves from q into laye; that is what was wanted of it. Sign in with Apple is laye's own, native.
  Proof: signing in to laye with Apple, Google and GitHub reaches no QNTX node.

- [ ] `P2P2A2A_A_003_04` A root verifies an ID in person before inviting: ID Verifier – Display Only, wanted in laye's invite flow. The system shows the verified ID on the root's phone; laye receives none of it.
  Proof: a root taps an invitee's iPhone, sees the ID Wallet verified, and invites; laye's store holds no ID data afterwards.

- [ ] `P2P2A2A_A_003_05` The island is its own repo, used by QNTX-App, laye, and any other app. What waits on a person stands on the phone as a Live Activity (ADR-060). QNTX-App's `island/` moves there with its CI (`island-tests`, `island-wall`, `island-draw`); each app takes it in, as `laye.ground.institute.island` in laye. Collections and approval packs (`_06`) are laye's, and laye starts what waits on laye's island.
  Proof: QNTX-App and laye each build the island from that repo, with nothing of it copied into either; an approval pack waiting on a person stands on laye's island, and a press on it answers the node.

- [ ] `P2P2A2A_A_003_10` A person interacts with agents through laye: what an agent says to them, what they say back, what waits on them. laye hosts no agent and owns no LLM gateway or automation; a QNTX node hosts agents, and is not the only host. laye meets an agent the same way wherever it runs, over A2A.
  Proof: a person speaks with an agent on q and with one hosted elsewhere from the same laye screen, and laye's store holds no model key.

- [ ] `P2P2A2A_A_003_09` Everything laye takes from QNTX-App lives in a repo of its own, generalised, which QNTX-App, laye and other apps use: the island, `sheet/`, signing against a profile (`ios-project.py`), registering App IDs and profiles (`apple.py`), the TestFlight upload, and waiting until testers can install (`delivered.py`). Neither app keeps a copy.
  Proof: QNTX-App's and laye's repos hold none of these files, both reach TestFlight, and a change in the shared repo reaches both.

- [ ] `P2P2A2A_A_003_06` laye is the A2A layer collections are placed into. What an agent says to an agent is held by laye for its receiver; a person adds to it, removes from it, and releases it. Collections and approval packs move from QNTX into laye (QNTX `server/collected.go` and the packs); a node places into them and is answered.
  Proof: one session says something to another through laye; it is held, a person releases it from the phone, and the other session receives it. A node's approval is a pack in laye, answered from the phone, and the node receives the answer.

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
