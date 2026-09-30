import { state } from "./state.js";
import { $, escapeHtml } from "./dom.js";

function filteredSortedPorts() {
  let rows = state.openPorts.slice();
  const q = state.portsSearch;
  if (q) {
    rows = rows.filter((p) =>
      String(p.port).includes(q) ||
      (p.service || "").toLowerCase().includes(q) ||
      (p.version || "").toLowerCase().includes(q) ||
      (p.banner || "").toLowerCase().includes(q));
  }
  const [key, dir] = state.portsSort.split("-");
  rows.sort((a, b) => {
    const av = key === "service" ? (a.service || "zzz").toLowerCase() : a.port;
    const bv = key === "service" ? (b.service || "zzz").toLowerCase() : b.port;
    if (av < bv) return dir === "asc" ? -1 : 1;
    if (av > bv) return dir === "asc" ? 1 : -1;
    return 0;
  });
  return rows;
}

export function renderPortsTable() {
  const tbody = document.querySelector("#portsTable tbody");
  const rows = filteredSortedPorts();
  $("portsEmpty").classList.toggle("hidden", state.openPorts.length > 0);
  $("portsNoMatch").classList.toggle("hidden", !(state.openPorts.length > 0 && rows.length === 0));

  tbody.innerHTML = rows.map((p) => {
    const expanded = state.expandedPorts.has(p.port);
    const related = state.findings.filter((f) => f.port === p.port);
    const service = escapeHtml(p.service || "Unknown") + (p.version ? ` <small>${escapeHtml(p.version)}</small>` : "");
    return `<tr class="port-row${expanded ? " expanded" : ""}" data-port="${Number(p.port)}">
      <td>${Number(p.port)}</td>
      <td><span class="badge badge-open">OPEN</span></td>
      <td>tcp</td>
      <td>${service}</td>
      <td>${escapeHtml((p.banner || "").slice(0, 60))}</td>
      <td><span class="expand-chevron">▶</span></td>
    </tr>
    <tr class="port-detail-row${expanded ? " open" : ""}" data-detail-for="${Number(p.port)}">
      <td colspan="6"><div class="detail-grid">
        <strong>Port</strong><span>${Number(p.port)}/tcp</span>
        <strong>Service</strong><span>${escapeHtml(p.service || "Unknown")}</span>
        <strong>Version</strong><span>${p.version ? escapeHtml(p.version) : "Not disclosed"}</span>
        <strong>Banner</strong><span>${p.banner ? escapeHtml(p.banner) : "No banner captured"}</span>
        <strong>Findings</strong><span>${related.length ? escapeHtml(related.map((f) => f.title).join("; ")) : "None for this port"}</span>
      </div></td>
    </tr>`;
  }).join("");

  tbody.querySelectorAll("tr.port-row").forEach((tr) => {
    tr.addEventListener("click", () => {
      const port = parseInt(tr.dataset.port, 10);
      if (state.expandedPorts.has(port)) state.expandedPorts.delete(port); else state.expandedPorts.add(port);
      renderPortsTable();
    });
  });
}

export function initPorts() {
  $("portsSearch").addEventListener("input", (e) => { state.portsSearch = e.target.value.trim().toLowerCase(); renderPortsTable(); });
  $("portsSort").addEventListener("change", (e) => { state.portsSort = e.target.value; renderPortsTable(); });
}
