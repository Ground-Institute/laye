// laye, on a phone: the key you are, and the accounts that prove it.
//
// The key is made here and never leaves this app. An account proves itself
// once, in the provider ceremony at CEREMONY, and the binding the ceremony
// signs is held beside the key. A node's login page hands its journey to the
// app as laye://sign?<journey>; the app answers laye's challenge with the key
// and the binding, and opens where laye sends you back to.

// "think of laye like an authentication app"
// "auth and identity"
// "laye is calm"

const LAYE = 'https://laye.ground.institute';
const CEREMONY = 'https://api.q.sbvh.nl';
// Where the ceremony returns to: a door the node names in am.toml.
const DOOR = 'laye://door';

const tauri = window.__TAURI__;
const ask = tauri?.http?.fetch ?? window.fetch.bind(window);

const said = (words, bad) => {
  const p = document.getElementById('said');
  p.textContent = words;
  p.className = bad ? 'bad' : '';
};

// The scene: drawn behind everything, told when laye knows you.
let scene = null;
import('./scene/laye_scene.js')
  .then(async (built) => { await built.default(); scene = built; drawn(); })
  .catch(() => { /* No scene built: the page stands on its own ground. */ });

function store() {
  return new Promise((ok, no) => {
    const open = indexedDB.open('laye', 2);
    open.onupgradeneeded = () => {
      for (const name of ['keys', 'held']) {
        if (!open.result.objectStoreNames.contains(name)) open.result.createObjectStore(name);
      }
    };
    open.onsuccess = () => ok(open.result);
    open.onerror = () => no(open.error);
  });
}

async function read(name, id) {
  const db = await store();
  return new Promise((ok, no) => {
    const get = db.transaction(name).objectStore(name).get(id);
    get.onsuccess = () => ok(get.result);
    get.onerror = () => no(get.error);
  });
}

async function write(name, id, value) {
  const db = await store();
  return new Promise((ok, no) => {
    const tx = db.transaction(name, 'readwrite');
    const done = value === undefined ? tx.objectStore(name).delete(id) : tx.objectStore(name).put(value, id);
    done.onsuccess = () => ok();
    done.onerror = () => no(done.error);
  });
}

async function key() {
  const held = await read('keys', 'me');
  if (held) return held;
  const made = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  await write('keys', 'me', made);
  return made;
}

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = '';
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = '1' + out; }
  return out;
}

const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');

async function me() {
  const pair = await key();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { pair, hex: hex(raw), did: 'did:key:z' + base58(new Uint8Array([0xed, 0x01, ...raw])) };
}

// The account this key is bound to, as the ceremony signed it.
const proven = () => read('held', 'binding');

async function prove(provider, host) {
  const self = await me();
  const asked = new URLSearchParams({ provider, peer_pubkey_hex: self.hex, door: DOOR });
  if (host) asked.set('host', host);
  const url = CEREMONY + '/auth/binding/go?' + asked;
  said('');
  let back;
  try {
    back = (await tauri.core.invoke('plugin:sheet|run', { url, scheme: 'laye' })).url;
  } catch (e) {
    if (String(e) === 'cancelled') return;
    // Off iOS there is no sheet: the browser runs the ceremony, and laye://
    // brings the ticket back.
    await tauri.opener.openUrl(url);
    return;
  }
  await cameBack(back);
}

// "So laye has its own island?"
// "I havent seen it yet."
// The island asks laye in the session this page holds, under the key the app
// names (apple.json island.session; ios-common island/app/WaitsNode.swift).
// laye gives one for this key and the account it is bound to, as it lets them
// log in; it lasts an hour, so it is asked for again while the page stands.
const SESSION = 'session';
const SESSION_AGAIN = 30 * 60 * 1000;

async function hold() {
  const held = await proven();
  if (!held) {
    try { localStorage.removeItem(SESSION); } catch { /* kept nowhere */ }
    return;
  }
  const self = await me();
  const { challenge } = await (await ask(LAYE + '/laye/challenge')).json();
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', self.pair.privateKey, new TextEncoder().encode(challenge)));
  const answer = await ask(LAYE + '/laye/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did: self.did, signature: b64url(signature), challenge, bindings: [held.binding] }),
  });
  const body = await answer.json();
  if (!answer.ok) { said('laye gave no session: ' + (body.error_description || body.error || answer.status), true); return; }
  localStorage.setItem(SESSION, body.session);
}

async function cameBack(url) {
  const ticket = new URL(url).searchParams.get('ceremony');
  if (!ticket) return;
  said('...');
  const answer = await ask(CEREMONY + '/auth/binding/result?ceremony=' + encodeURIComponent(ticket));
  if (!answer.ok) { said('The account was not proven: ' + answer.status, true); return; }
  const { binding, name, picture } = await answer.json();
  await write('held', 'binding', { binding, name, picture });
  said('');
  await drawn();
  await hold();
}

// A node's journey, handed over by its login page: laye's challenge answered
// with this key and the account it holds, and the browser sent where laye says.
async function signIn(journey) {
  const self = await me();
  const held = await proven();
  said('...');
  const { challenge } = await (await ask(LAYE + '/laye/challenge')).json();
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', self.pair.privateKey, new TextEncoder().encode(challenge)));
  const answer = await ask(LAYE + '/laye/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      did: self.did,
      signature: b64url(signature),
      challenge,
      bindings: held ? [held.binding] : [],
      authorize: journey,
    }),
  });
  const body = await answer.json();
  if (!answer.ok) { said(body.error_description || 'laye did not let you in', true); return; }
  said('');
  await tauri.opener.openUrl(body.redirect);
}

async function arrived(url) {
  const at = new URL(url);
  if (at.host === 'door') return cameBack(url);
  if (at.host === 'sign') return signIn(at.search.replace(/^\?/, ''));
}

function press(words, quiet, then) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = words;
  if (quiet) button.className = 'quiet';
  button.addEventListener('click', () => then().catch((e) => said(String(e), true)));
  return button;
}

// One drawing at a time: the scene arriving and the page starting both ask.
let drawing = Promise.resolve();
const drawn = () => (drawing = drawing.then(draw, draw));

async function draw() {
  const held = await proven();
  scene?.known(Boolean(held));
  const presses = document.getElementById('presses');
  const shown = [];
  const you = document.getElementById('you');
  you.hidden = !held;
  if (held) {
    const claim = held.binding?.claim ?? {};
    document.getElementById('name').textContent = held.name || claim.canonical_id || '';
    document.getElementById('account').textContent = held.name ? claim.canonical_id ?? '' : (await me()).did;
    shown.push(press('forget this account', true, async () => {
      await write('held', 'binding', undefined);
      await hold();
      await drawn();
    }));
    presses.replaceChildren(...shown);
    return;
  }
  const { providers } = await (await ask(CEREMONY + '/auth/binding/providers?door=' + encodeURIComponent(DOOR))).json();
  for (const p of providers.filter((p) => p.kind === 'redirect')) {
    shown.push(press('Sign in with ' + p.label, false, async () => {
      let host = '';
      if (p.host_prompt) {
        host = prompt(p.host_prompt, p.host_placeholder);
        if (!host) return;
      }
      await prove(p.id, host);
    }));
  }
  presses.replaceChildren(...shown);
}

async function begin() {
  if (!('subtle' in crypto)) { said('This device cannot make a key here.', true); return; }
  await drawn();
  hold().catch((e) => said(String(e), true));
  setInterval(() => hold().catch((e) => said(String(e), true)), SESSION_AGAIN);
  const deepLink = tauri?.deepLink;
  if (!deepLink) return;
  for (const url of (await deepLink.getCurrent()) ?? []) await arrived(url);
  await deepLink.onOpenUrl((urls) => urls.forEach((url) => arrived(url).catch((e) => said(String(e), true))));
}

begin().catch((e) => said(String(e), true));
