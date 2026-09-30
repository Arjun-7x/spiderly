import { state } from "./state.js";
import { $, setDot } from "./dom.js";
import { apiFetch } from "./api.js";

export function setWsStatus(text, ok, pending = false) {
  setDot("wsDot", ok, pending);
  $("wsStatus").textContent = text;
}

export async function pingBackend() {
  const label = $("backendStatus"), dbLabel = $("dbStatus"), about = $("aboutBackendStatus");
  try {
    const res = await apiFetch(`${state.apiBase}/api/status`, { cache: "no-store" });
    if (!res.ok) throw new Error("bad status");
    const data = await res.json();
    setDot("backendDot", true);
    label.textContent = data.auth_required && !state.apiKey
      ? `Online · v${data.version} · API key required`
      : `Online · v${data.version}`;
    const dbOk = data.database === "connected";
    setDot("dbDot", dbOk);
    dbLabel.textContent = dbOk ? "Connected" : "Unavailable";
    if (about) about.textContent = "online";
  } catch {
    setDot("backendDot", false);
    setDot("dbDot", false);
    label.textContent = "Unreachable";
    dbLabel.textContent = "Unknown";
    if (about) about.textContent = "offline — check the API URL in Settings";
  }
}

export function initStatus() {
  pingBackend();
  return setInterval(pingBackend, 8000);
}
