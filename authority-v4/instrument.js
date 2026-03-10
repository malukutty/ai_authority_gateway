const Sentry = require("@sentry/node");
const { nodeProfilingIntegration } = require("@sentry/profiling-node");

Sentry.init({
  dsn: "https://bb71318c2c203109e2c8dbcdce4e3fe9@o4511017404334080.ingest.us.sentry.io/4511017469935616",

  integrations: [
    nodeProfilingIntegration(),
  ],

  enableLogs: true,

  tracesSampleRate: 1.0,

  profileSessionSampleRate: 1.0,

  profileLifecycle: "trace",

  sendDefaultPii: false
});