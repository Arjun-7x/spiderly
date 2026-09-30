import { state } from "./state.js";
import { $, escapeHtml } from "./dom.js";

export function renderFindings() {
  $("findingsEmpty").classList.toggle("hidden", state.findings.length > 0);
  $("findingsList").innerHTML = state.findings.map((f) => {
    const sev = (f.severity || "INFORMATIONAL").toLowerCase();
    return `<div class="finding-card sev-${escapeHtml(sev)}">
      <div class="finding-top"><span class="sev-pill sev-${escapeHtml(sev)}">${escapeHtml(f.severity || "")}</span><h4>${escapeHtml(f.title)}</h4></div>
      ${f.description ? `<p>${escapeHtml(f.description)}</p>` : ""}
      ${f.evidence ? `<div class="finding-evidence">${escapeHtml(f.evidence)}</div>` : ""}
      ${f.recommendation ? `<div class="finding-evidence"><strong>Recommendation:</strong> ${escapeHtml(f.recommendation)}</div>` : ""}
    </div>`;
  }).join("");
}
