// What the screen shows, photographed after real seconds over Chrome's
// DevTools protocol, at a phone's size:
//
//   node screens.mjs <devtools-port> <url> <ms>:<out.png> ...
//
// Real seconds, not virtual time: the scene moves by the clock.
import { writeFileSync } from 'node:fs';

const [port, url, ...shots] = process.argv.slice(2);
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((ok, no) => { ws.onopen = ok; ws.onerror = no; });
let id = 0;
const waiting = new Map();
ws.onmessage = (m) => {
  const said = JSON.parse(m.data);
  if (waiting.has(said.id)) { waiting.get(said.id)(said); waiting.delete(said.id); }
};
const send = (method, params = {}) => new Promise((ok) => { waiting.set(++id, ok); ws.send(JSON.stringify({ id, method, params })); });
await send('Emulation.setDeviceMetricsOverride', { width: 430, height: 860, deviceScaleFactor: 2, mobile: true });
await send('Page.navigate', { url });
const start = Date.now();
for (const shot of shots) {
  const [ms, out] = shot.split(':');
  await new Promise((r) => setTimeout(r, Math.max(0, Number(ms) - (Date.now() - start))));
  const said = await send('Page.captureScreenshot', { format: 'png' });
  if (!said.result) throw new Error(`no screenshot for ${out}: ${JSON.stringify(said.error)}`);
  writeFileSync(out, Buffer.from(said.result.data, 'base64'));
  console.log('photographed', out);
}
ws.close();
await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`);
