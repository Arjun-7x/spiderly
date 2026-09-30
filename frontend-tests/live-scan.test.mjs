import test from "node:test";
import assert from "node:assert/strict";
import { boot, tick } from "./harness.mjs";

const SCAN = { scan_id: "abc123", target: "10.0.0.5", scan_mode: "custom", port_spec: "22,80", status: "running" };
let app;

test("boot: status ping, same-origin default API base, empty states", async () => {
  app = await boot({
    routes: {
      "/api/status": { body: { version: "0.2.0", database: "connected", auth_required: false } },
      "POST /api/scans": { body: SCAN },
      "POST /api/scans/abc123/cancel": { body: { status: "cancelling" } },
      "/api/scans/abc123/results": { body: { scan: { status: "completed" }, ports: [{ port: 22, state: "open", service_guess: "SSH", version: "OpenSSH 9.6p1", banner: "SSH-2.0-OpenSSH_9.6p1" }], findings: [{ title: "Open TCP port 22", severity: "INFORMATIONAL", port: 22, description: "d", evidence: "e", recommendation: "r" }] } },
    },
  });
  await tick(20);
  assert.equal(app.$("backendStatus").textContent, "Online · v0.2.0");
  assert.equal(app.$("apiBaseInput").value, "http://localhost:8000");
  assert.equal(app.calls[0].path, "/api/status");
});

test("submitting the form posts the payload, opens the dashboard and the WebSocket", async () => {
  app.$("targetInput").value = "10.0.0.5";
  app.$("modeInput").value = "custom";
  app.$("modeInput").dispatchEvent(new app.window.Event("change"));
  app.$("customPortsInput").value = "22,80";
  app.$("scanForm").dispatchEvent(new app.window.Event("submit", { cancelable: true }));
  await tick(20);

  const post = app.calls.find((c) => c.method === "POST" && c.path === "/api/scans");
  assert.deepEqual(post.body, { target: "10.0.0.5", scan_mode: "custom", port_spec: "22,80" });
  assert.ok(app.$("page-dashboard").classList.contains("active"));
  assert.ok(!app.$("portsEmpty").classList.contains("hidden"), "empty state shown for a fresh scan");
  assert.equal(app.ws().url, "ws://localhost:8000/api/ws/scans/abc123");
  assert.equal(app.$("cancelScanBtn").style.display, "inline-block");
  assert.match(app.$("reportLink").href, /\/api\/reports\/abc123$/);
});

test("live events update stats, table (incl. version) and graph; hostile banners stay inert", async () => {
  const ws = app.ws();
  ws.open();
  assert.equal(app.$("wsStatus").textContent, "Connected");
  ws.push({ event_type: "host.discovered", message: "m", data: { address: "10.0.0.5", reachable: true } });
  ws.push({ event_type: "port.discovered", message: "m", data: { port: 22, service_guess: "SSH", progress: { scanned: 1, total: 2 } } });
  ws.push({ event_type: "port.discovered", message: "m", data: { port: 80, service_guess: "HTTP" } });
  ws.push({ event_type: "service.detected", message: "m", data: { port: 22, service: "SSH", version: "OpenSSH 9.6p1", banner: "SSH-2.0-OpenSSH_9.6p1" } });
  ws.push({ event_type: "service.detected", message: "m", data: { port: 80, service: "HTTP", banner: "<img src=x onerror=alert(1)>" } });
  ws.push({ event_type: "finding.created", message: "<b>bold</b> finding", data: { severity: "LOW", port: 80 } });

  assert.equal(app.$("statHosts").textContent, "1");
  assert.equal(app.$("statPorts").textContent, "2");
  assert.equal(app.$("statServices").textContent, "2");
  assert.equal(app.$("statFindings").textContent, "1");
  assert.equal(app.$("portProgLabel").textContent, "50%");
  const rows = app.document.querySelectorAll("#portsTable tr.port-row");
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /OpenSSH 9\.6p1/);
  assert.equal(app.document.querySelectorAll("#portsTable img, #eventStream img, #eventStream b").length, 0, "no HTML injected");
  assert.equal(app.document.querySelectorAll("#networkSvg .node-circle").length, 3); // target + 2 ports
});

test("ports search + sort + row expansion", async () => {
  const search = app.$("portsSearch");
  search.value = "openssh";
  search.dispatchEvent(new app.window.Event("input"));
  assert.equal(app.document.querySelectorAll("#portsTable tr.port-row").length, 1);
  search.value = "nomatch";
  search.dispatchEvent(new app.window.Event("input"));
  assert.ok(!app.$("portsNoMatch").classList.contains("hidden"));
  search.value = "";
  search.dispatchEvent(new app.window.Event("input"));
  app.$("portsSort").value = "port-desc";
  app.$("portsSort").dispatchEvent(new app.window.Event("change"));
  assert.equal(app.document.querySelector("#portsTable tr.port-row").dataset.port, "80");
  app.document.querySelector("#portsTable tr.port-row").click();
  assert.ok(app.document.querySelector("#portsTable tr.port-detail-row.open"));
});

test("cancel button calls the API, then scan.cancelled hides it", async () => {
  app.$("cancelScanBtn").click();
  await tick(20);
  assert.ok(app.calls.some((c) => c.method === "POST" && c.path === "/api/scans/abc123/cancel"));
  app.ws().push({ event_type: "scan.cancelled", message: "Scan cancelled.", data: {} });
  assert.equal(app.$("cancelScanBtn").style.display, "none");
  assert.equal(app.$("dashSub").textContent, "Scan cancelled.");
});

test("a finished/cancelled scan closing its stream does NOT trigger reconnect", async () => {
  const count = () => (globalThis.WebSocket.instances || []).length;
  const n = count();
  app.ws().serverClose(); // status is 'cancelled' -> no reconnect
  await tick(50);
  assert.equal(count(), n);
  assert.equal(app.$("wsStatus").textContent, "Disconnected");
});

test("completed event refreshes full results (findings with ports, persisted versions)", async () => {
  // start a fresh scan view so status is running again
  app.$("scanForm").dispatchEvent(new app.window.Event("submit", { cancelable: true }));
  await tick(20);
  const ws = app.ws();
  ws.open();
  ws.push({ event_type: "port.discovered", message: "m", data: { port: 22, service_guess: "SSH" } });
  ws.push({ event_type: "scan.completed", message: "done", data: { open_ports: [22], duration_seconds: 1.5 } });
  await tick(30);
  assert.equal(app.$("statDuration").textContent, "1.5s");
  assert.equal(app.document.querySelectorAll("#findingsList .finding-card").length, 1);
  assert.match(app.document.querySelector("#portsTable tr.port-row").textContent, /OpenSSH 9\.6p1/);
  app.document.querySelector("#portsTable tr.port-row").click();
  assert.match(app.document.querySelector("#portsTable .detail-grid").textContent, /Open TCP port 22/, "findings link to their port");
  process.exit(0);
});
