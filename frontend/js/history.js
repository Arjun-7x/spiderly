import { state } from "./state.js";
import { $, escapeHtml, showToast } from "./dom.js";
import { apiFetch, withKey } from "./api.js";
import { onPageShow, showPage } from "./nav.js";
import { setWsStatus } from "./status.js";
import { renderPortsTable } from "./ports.js";
import { renderFindings } from "./findings.js";
import { initGraph, addGraphPort } from "./graph.js";
import { closeLiveConnection, connectToScan, updateCancelButton } from "./live.js";

const skeleton = () => Array.from({ length: 3 }).map(() => `
  <div class="skeleton-item"><div class="skeleton-line" style="width: 40%;"></div><div class="skeleton-line" style="width: 65%;"></div></div>`).join("");

export async function loadHistory() {
  $("historyList").innerHTML = skeleton();
  try {
    const res = await apiFetch(`${state.apiBase}/api/scans`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state.historyCache = (await res.json()) || [];
    renderHistoryList();
  } catch {
    $("historyList").innerHTML = `<div class="empty-state">SPIDERLY engine is offline or refused the request — unable to load history.</div>`;
  }
}

export function renderHistoryList() {
  const container = $("historyList");
  let scans = state.historyCache;
  if (!scans.length) {
    container.innerHTML = `<div class="empty-state"><div class="big">☰</div>No scans yet. Start one from the Scanner tab.</div>`;
    return;
  }
  if (state.historySearch) scans = scans.filter((s) => s.target.toLowerCase().includes(state.historySearch));
  if (!scans.length) {
    container.innerHTML = `<div class="empty-state"><div class="big">⌕</div>No scans match "${escapeHtml(state.historySearch)}".</div>`;
    return;
  }
  container.innerHTML = scans.map((s) => `
    <div class="history-item">
      <div class="history-left">
        <b>${escapeHtml(s.target)}</b>
        <div class="sub">${Number(s.open_port_count)} open ports · ${Number(s.finding_count)} findings · ${escapeHtml(s.scan_mode)}</div>
      </div>
      <div style="display:flex; align-items:center; gap:12px;">
        <span class="history-status ${escapeHtml(s.status)}">${escapeHtml(s.status)}</span>
        <button class="btn btn-ghost" data-view="${escapeHtml(s.id)}">View</button>
      </div>
    </div>`).join("");
  container.querySelectorAll("[data-view]").forEach((btn) => btn.addEventListener("click", () => viewPastScan(btn.dataset.view)));
}

export async function viewPastScan(scanId) {
  try {
    const res = await apiFetch(`${state.apiBase}/api/scans/${scanId}/results`);
    if (!res.ok) throw new Error("Scan not found.");
    const data = await res.json();

    closeLiveConnection();
    state.currentScanId = scanId;
    state.currentScanStatus = data.scan.status;
    updateCancelButton();
    $("cancelScanBtn").disabled = false;
    state.expandedPorts = new Set();
    state.portsSearch = "";
    $("portsSearch").value = "";
    state.openPorts = (data.ports || []).filter((p) => p.state === "open")
      .map((p) => ({ port: p.port, service: p.service_guess, version: p.version, banner: p.banner }));
    state.findings = data.findings || [];

    $("dashSub").textContent = `Target: ${data.scan.target} · Mode: ${data.scan.scan_mode} · Status: ${data.scan.status}`;
    $("statHosts").textContent = (data.hosts || []).length;
    $("statPorts").textContent = state.openPorts.length;
    $("statServices").textContent = new Set(state.openPorts.map((p) => p.service)).size;
    $("statFindings").textContent = state.findings.length;
    const { completed_at: end, started_at: start } = data.scan;
    $("statDuration").textContent = end && start ? `${(end - start).toFixed(2)}s` : "—";
    const running = data.scan.status === "running";
    $("progressPanel").classList.toggle("hidden", !running);
    $("reportLink").href = withKey(`${state.apiBase}/api/reports/${scanId}`);
    $("eventStream").innerHTML = "";
    $("scanIdValue").textContent = scanId;
    $("scanIdTag").classList.remove("hidden");

    renderPortsTable();
    renderFindings();
    initGraph(data.scan.target);
    state.openPorts.forEach((p) => addGraphPort(p.port, p.service));
    showPage("dashboard");

    if (running) {
      // A scan still in flight: attach to its live stream (history is replayed, then live events).
      state.openPorts = []; state.findings = [];
      for (const id of ["statHosts", "statPorts", "statServices", "statFindings"]) $(id).textContent = "0";
      initGraph(data.scan.target);
      connectToScan(scanId, data.scan.target);
    } else {
      setWsStatus("Idle (viewing past scan)", false);
    }
  } catch {
    showToast("Could not load that scan.", "error");
  }
}

export function initHistory() {
  onPageShow("history", loadHistory);
  $("refreshHistoryBtn").addEventListener("click", loadHistory);
  $("historySearch").addEventListener("input", (e) => { state.historySearch = e.target.value.trim().toLowerCase(); renderHistoryList(); });
}
