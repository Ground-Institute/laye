// "I want a new node, on cloudflare, called C"

// "i want to get the max out of the free tier"

// 「[Opus 5.5] C holds one Peer: every WebSocket C takes is held by that one
// Durable Object, so laye-net's listening transport has one place to live.」
export class Peer {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("C takes a WebSocket here\n", { status: 426 });
    }
    const [client, server] = Object.values(new WebSocketPair());
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketClose(ws, code, reason) {
    ws.close(code, reason);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      const held = await env.PEER.get(env.PEER.idFromName("c")).fetch(new Request(url.origin + "/held"));
      return Response.json({ c: "up", peer: held.status === 426 ? "answers" : held.status });
    }
    return env.PEER.get(env.PEER.idFromName("c")).fetch(request);
  },
};
