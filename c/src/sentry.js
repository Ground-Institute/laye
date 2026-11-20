// "use standard normal software and packages so we have to most default boring sentry setup"

// "i prefer the shape of OTEL."

// 「[Opus 5.5] C as worker-build makes it, wrapped by @sentry/cloudflare as its
// docs show: the Worker with withSentry, the Durable Object with
// instrumentDurableObjectWithSentry. The Rust is untouched.」

import * as Sentry from "@sentry/cloudflare";
import C, { Peer as RustPeer } from "../build/index.js";

const options = (env) => ({
  dsn: env.SENTRY_DSN,
  environment: "c-stack",
  tracesSampleRate: 1.0,
  enableLogs: true,
  sendDefaultPii: false,
});

export const Peer = Sentry.instrumentDurableObjectWithSentry(options, RustPeer);

export default Sentry.withSentry(options, C);
