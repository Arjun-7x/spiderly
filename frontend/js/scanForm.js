import { state } from "./state.js";
import { $, showToast } from "./dom.js";
import { apiFetch, withKey } from "./api.js";
import { showPage } from "./nav.js";
import { initGraph } from "./graph.js";
import { connectToScan, updateCancelButton } from "./live.js";

export function resetDashboardForNewScan(meta) {
  state.currentScanId = meta.scan_id;
  state.currentScanStatus = "running";
  $("cancelScanBtn").disabled = false;
  updateCancelButton();
  state.openPorts = [];
  state.findings = [];
  state.expandedPorts = new Set();
  state.portsSearch = "";
  $("portsSearch").value = "";

  $("dashSub").textContent = `Target: ${meta.target} · Mode: ${meta.scan_mode}`;
  for (const id of ["statHosts", "statPorts", "statServices", "statFindings"]) $(id).textContent = "0";
  $("statDuration").textContent = "—";
  $("eventStream").innerHTML = "";
  document.querySelector("#portsTable tbody").innerHTML = "";
  $("portsEmpty").classList.remove("hidden");
  $("portsNoMatch").classList.add("hidden");
  $("findingsList").innerHTML = "";
  $("findingsEmpty").classList.remove("hidden");
  $("progressPanel").classList.remove("hidden");
  $("portProgFill").style.width = "0%";
  $("portProgLabel").textContent = "0%";
  $("reportLink").href = withKey(`${state.apiBase}/api/reports/${meta.scan_id}`);
  $("scanIdValue").textContent = meta.scan_id;
  $("scanIdTag").classList.remove("hidden");
  initGraph(meta.target);
}

function fail(message) {
  const el = $("scanError");
  el.textContent = message;
  el.style.display = "block";
}

export function initScanForm() {
  const mode = $("modeInput");
  mode.addEventListener("change", () => { $("customPortField").style.display = mode.value === "custom" ? "block" : "none"; });

  $("copyScanIdBtn").addEventListener("click", async () => {
    const btn = $("copyScanIdBtn");
    try {
      await navigator.clipboard.writeText($("scanIdValue").textContent);
      btn.classList.add("copied");
      showToast("Scan ID copied to clipboard.", "success", 2000);
      setTimeout(() => btn.classList.remove("copied"), 1200);
    } catch { showToast("Could not copy to clipboard.", "error"); }
  });

  $("scanForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (state.currentScanStatus === "running" && !confirm(
      "A scan is already in progress. Starting a new scan will replace the current live dashboard view (the running scan keeps going in the background and stays in Scan History). Continue?")) return;

    $("scanError").style.display = "none";
    const target = $("targetInput").value.trim();
    const scan_mode = mode.value;
    const port_spec = $("customPortsInput").value.trim();
    if (!target) return fail("Please enter a target IP address or hostname.");
    if (scan_mode === "custom" && !port_spec) return fail("Custom scan mode requires a port range (e.g. 1-1000,8080).");

    const payload = { target, scan_mode };
    if (scan_mode === "custom") payload.port_spec = port_spec;

    const btn = $("startScanBtn");
    btn.disabled = true;
    btn.textContent = "Starting…";
    try {
      const res = await apiFetch(`${state.apiBase}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to start scan.");
      resetDashboardForNewScan(data);
      showPage("dashboard");
      connectToScan(data.scan_id, data.target);
      showToast(`Scan started against ${data.target}.`, "success");
    } catch (err) {
      const msg = err.message || "Could not reach the SPIDERLY engine. Is the backend running?";
      fail(msg);
      showToast(msg, "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Start Scan";
    }
  });
}
