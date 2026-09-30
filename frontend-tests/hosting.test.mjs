import test from "node:test";
import assert from "node:assert/strict";
import { boot, tick, FakeWebSocket } from "./harness.mjs";

// Simulates the app served by the backend on an https host (e.g. Render): no port in the URL.
test("hosted at https origin without :8000 -> same-origin API and wss:// WebSocket", async () => {
  const app = await boot({
    url: "https://spiderly.onrender.com/",
    routes: {
      "/api/status": { body: { version: "0.3.0", database: "connected", auth_required: true } },
      "POST /api/scans": { body: { scan_id: "r1", target: "203.0.113.10", scan_mode: "quick", status: "running" } },
    },
    storage: { spiderly_api_key: "k" },
  });
  await tick(30);
  assert.equal(app.$("apiBaseInput").value, "https://spiderly.onrender.com");
  assert.equal(app.calls.at(-1).url.startsWith("https://spiderly.onrender.com/api/status"), true);
  app.$("targetInput").value = "203.0.113.10";
  app.$("scanForm").dispatchEvent(new app.window.Event("submit", { cancelable: true }));
  await tick(30);
  assert.equal(app.ws().url, "wss://spiderly.onrender.com/api/ws/scans/r1?api_key=k");
  process.exit(0);
});
