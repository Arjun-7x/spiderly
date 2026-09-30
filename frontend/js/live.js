// Live scan stream: WebSocket (with reconnect), event handling, progress, cancel.
import { state } from "./state.js";
import { $, escapeHtml, showToast } from "./dom.js";
import { apiFetch, withKey } from "./api.js";
import { setWsStatus } from "./status.js";
import { renderPortsTable } from "./ports.js";
import { renderFindings } from "./findings.js";
import { addGraphHost, addGraphPort } from "./graph.js";

const TERMINAL = new Set(["completed", "failed", "cancelled", "interrupted"]);

export function updateCancelButton() {
  $("cancelScanBtn").style.display = state.currentScanStatus === "running" ? "inline-block" : "none";
}

export function updateProgress(scanned, total) {
  const pct = total > 0 ? Math.min(100, Math.round((scanned / total) * 100)) : 0;
  $("portProgFill").style.width = `${pct}%`;
  $("portProgLabel").textContent = `${pct}%`;
}

export function logEvent(evt) {
  const stream = $("eventStream");
  const line = document.createElement("div");
  line.className = "event-line";
  const type = (evt.event_type || "log").split(".")[0];
  const time = new Date((evt.created_at || Date.now() / 1000) * 1000).toLocaleTimeString();
  line.innerHTML = `<span class="event-time">[${escapeHtml(time)}]</span><span class="event-type-${escapeHtml(type)}">${escapeHtml(evt.message || "")}</span>`;
  stream.prepend(line);
  while (stream.children.length > 200) stream.removeChild(stream.lastChild);
}

export async function refreshFullResults() {
  if (!state.currentScanId) return;
  try {
    const res = await apiFetch(`${state.apiBase}/api/scans/${state.currentScanId}/results`);
    if (!res.ok) return;
    const data = await res.json();
    state.findings = data.findings || [];
    // Adopt the persisted versions/banners too, so the table matches history exactly.
    for (const p of data.ports || []) {
      const live = state.openPorts.find((x) => x.port === p.port);
      if (live) { live.version = p.version; live.banner = p.banner || live.banner; live.service = p.service_guess || live.service; }
    }
    $("statFindings").textContent = state.findings.length;
    renderFindings();
    renderPortsTable();
  } catch { /* non-fatal */ }
}

export function handleEvent(evt) {
  logEvent(evt);
  const t = evt.event_type;
  const d = evt.data || {};

  if (t === "host.discovered") {
    $("statHosts").textContent = (parseInt($("statHosts").textContent, 10) || 0) + 1;
    addGraphHost(d.address, d.reachable);
  } else if (t === "port.discovered") {
    state.openPorts.push({ port: d.port, service: d.service_guess, version: null, banner: null });
    $("statPorts").textContent = state.openPorts.length;
    renderPortsTable();
    addGraphPort(d.port, d.service_guess);
    if (d.progress) updateProgress(d.progress.scanned, d.progress.total);
  } else if (t === "progress" && d.progress) {
    updateProgress(d.progress.scanned, d.progress.total);
  } else if (t === "service.detected") {
    const p = state.openPorts.find((x) => x.port === d.port);
    if (p) { p.service = d.service; p.banner = d.banner; p.version = d.version || null; renderPortsTable(); }
    $("statServices").textContent = new Set(state.openPorts.map((x) => x.service)).size;
  } else if (t === "finding.created") {
    state.findings.push({ severity: d.severity, port: d.port, title: evt.message });
    $("statFindings").textContent = state.findings.length;
    $("findingsEmpty").classList.add("hidden");
  } else if (t === "scan.completed") {
    state.currentScanStatus = "completed";
    updateCancelButton();
    updateProgress(1, 1);
    $("statDuration").textContent = `${d.duration_seconds}s`;
    refreshFullResults();
    showToast(`Scan complete — ${d.open_ports ? d.open_ports.length : state.openPorts.length} open port(s) found.`, "success");
  } else if (t === "scan.cancelled") {
    state.currentScanStatus = "cancelled";
    updateCancelButton();
    $("dashSub").textContent = "Scan cancelled.";
    showToast("Scan cancelled.", "info");
  } else if (t === "scan.failed") {
    state.currentScanStatus = "failed";
    updateCancelButton();
    $("dashSub").textContent = `Scan failed: ${d.error || "unknown error"}`;
    showToast(`Scan failed: ${d.error || "unknown error"}`, "error");
  }
}

export function closeLiveConnection() {
  if (state.wsReconnectTimer) { clearTimeout(state.wsReconnectTimer); state.wsReconnectTimer = null; }
  if (state.ws) { try { state.ws.close(); } catch { /* already closed */ } }
}

export function connectToScan(scanId, target) {
  closeLiveConnection();
  state.wsReconnectAttempts = 0;
  openSocket(scanId, target);
}

function openSocket(scanId, target) {
  const wsBase = state.apiBase.replace(/^http/, "ws");
  setWsStatus("Connecting…", false, true);
  const ws = new WebSocket(withKey(`${wsBase}/api/ws/scans/${scanId}`));
  state.ws = ws;

  ws.onopen = () => { state.wsReconnectAttempts = 0; setWsStatus("Connected", true); };
  ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      if (data.event_type === "error") { showToast(data.message || "Scan stream error.", "error"); return; }
      handleEvent(data);
    } catch { /* ignore malformed */ }
  };
  ws.onerror = () => logEvent({ event_type: "log", message: "WebSocket connection issue.", created_at: Date.now() / 1000 });
  ws.onclose = () => {
    setWsStatus("Disconnected", false);
    // Reconnect only while *this* scan is still running; a finished scan closing its stream is expected.
    if (state.currentScanId === scanId && state.currentScanStatus === "running" && state.wsReconnectAttempts < 5) {
      state.wsReconnectAttempts += 1;
      const delay = Math.min(1000 * 2 ** state.wsReconnectAttempts, 15000);
      setWsStatus(`Reconnecting in ${Math.round(delay / 1000)}s…`, false, true);
      state.wsReconnectTimer = setTimeout(() => openSocket(scanId, target), delay);
    }
  };
}

export function initCancel() {
  const btn = $("cancelScanBtn");
  btn.addEventListener("click", async () => {
    if (!state.currentScanId || !confirm("Cancel the running scan?")) return;
    try {
      const res = await apiFetch(`${state.apiBase}/api/scans/${state.currentScanId}/cancel`, { method: "POST" });
      if (!res.ok) throw new Error((await res.json()).detail || "Could not cancel scan.");
      btn.disabled = true;
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

export { TERMINAL };
