import test from "node:test";
import assert from "node:assert/strict";
import { boot, tick, FakeWebSocket } from "./harness.mjs";

let app;
const SCAN = { scan_id: "s1", target: "10.0.0.5", scan_mode: "quick", status: "running" };
const HISTORY = [
  { id: "s1", target: "10.0.0.5", scan_mode: "quick", status: "running", open_port_count: 0, finding_count: 0 },
  { id: "s2", target: "<b>evil</b>", scan_mode: "quick", status: "cancelled", open_port_count: 1, finding_count: 2 },
];

test("stored API key is sent as a header, and appended to WS + report URLs", async () => {
  app = await boot({
    storage: { spiderly_api_key: "k3y" },
    routes: {
      "/api/status": { body: { version: "0.2.0", database: "connected", auth_required: true } },
      "POST /api/scans": { body: SCAN },
      "/api/scans": { body: HISTORY },
    },
  });
  await tick(20);
  // calls[0] is the same-origin probe (status is public, no key needed); the ping that follows carries it.
  assert.equal(app.calls.filter((c) => c.path === "/api/status").at(-1).headers["X-API-Key"], "k3y");
  assert.equal(app.$("backendStatus").textContent, "Online · v0.2.0"); // key present -> no "key required" hint

  app.$("targetInput").value = "10.0.0.5";
  app.$("scanForm").dispatchEvent(new app.window.Event("submit", { cancelable: true }));
  await tick(20);
  assert.equal(app.calls.find((c) => c.method === "POST").headers["X-API-Key"], "k3y");
  assert.match(app.ws().url, /\/api\/ws\/scans\/s1\?api_key=k3y$/);
  assert.match(app.$("reportLink").href, /\/api\/reports\/s1\?api_key=k3y$/);
});

test("settings save persists the key and clears it when emptied", async () => {
  app.$("apiKeyInput").value = "newkey";
  app.$("saveApiBaseBtn").click();
  assert.equal(app.store.get("spiderly_api_key"), "newkey");
  await tick(10);
  assert.equal(app.calls.at(-1).headers["X-API-Key"], "newkey");
  app.$("apiKeyInput").value = "";
  app.$("saveApiBaseBtn").click();
  assert.equal(app.store.get("spiderly_api_key"), "");
});

test("a running scan whose socket drops reconnects with backoff", async () => {
  const ws = app.ws();
  ws.open();
  const n = FakeWebSocket.instances.length;
  ws.serverClose(); // status still 'running' -> schedule reconnect (2s)
  assert.match(app.$("wsStatus").textContent, /Reconnecting in 2s/);
  await tick(2200);
  assert.equal(FakeWebSocket.instances.length, n + 1);
  assert.match(app.ws().url, /\/api\/ws\/scans\/s1/);
});

test("history: renders statuses safely; viewing a running scan attaches the live stream", async () => {
  app.document.querySelector('.nav-item[data-page="history"]').click();
  await tick(30);
  const items = app.document.querySelectorAll("#historyList .history-item");
  assert.equal(items.length, 2);
  assert.ok(app.document.querySelector(".history-status.cancelled"));
  assert.equal(app.document.querySelectorAll("#historyList b b").length, 0, "target text is escaped");

  const n = FakeWebSocket.instances.length;
  const orig = globalThis.fetch;
  globalThis.fetch = async (u, o) => (String(u).endsWith("/api/scans/s1/results")
    ? { ok: true, status: 200, json: async () => ({ scan: { status: "running", target: "10.0.0.5", scan_mode: "quick", started_at: 1 }, hosts: [], ports: [], findings: [] }) }
    : orig(u, o));
  app.document.querySelector('[data-view="s1"]').click();
  await tick(30);
  assert.equal(FakeWebSocket.instances.length, n + 1, "attached to live stream");
  assert.equal(app.$("cancelScanBtn").style.display, "inline-block");
  assert.equal(app.$("statHosts").textContent, "0");
});

test("401 surfaces a helpful toast once", async () => {
  globalThis.fetch = async () => ({ ok: false, status: 401, json: async () => ({ detail: "Missing or invalid API key." }) });
  app.document.querySelector('.nav-item[data-page="history"]').click();
  await tick(30);
  const toasts = [...app.document.querySelectorAll("#toastStack .toast")].filter((t) => /requires an API key/.test(t.textContent));
  assert.equal(toasts.length, 1);
  assert.match(app.$("historyList").textContent, /refused the request/);
  process.exit(0);
});
