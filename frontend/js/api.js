import { state } from "./state.js";
import { showToast } from "./dom.js";

let authToastShown = false;

// fetch() that adds the optional X-API-Key and explains 401/429 once, clearly.
export async function apiFetch(url, opts = {}) {
  if (state.apiKey) opts.headers = { ...(opts.headers || {}), "X-API-Key": state.apiKey };
  const res = await fetch(url, opts);
  if (res.status === 401 && !authToastShown) {
    authToastShown = true;
    showToast("The backend requires an API key. Enter it under Settings.", "error", 6000);
    setTimeout(() => { authToastShown = false; }, 15000);
  }
  return res;
}

// For places that can't set headers (report links, WebSocket URLs).
export function withKey(url) {
  return state.apiKey ? `${url}${url.includes("?") ? "&" : "?"}api_key=${encodeURIComponent(state.apiKey)}` : url;
}

export const LOCAL_API = "http://127.0.0.1:8000";

// If the user hasn't chosen an API URL, use this page's origin when it actually
// hosts the API (probe /api/status); otherwise fall back to the local default
// (e.g. frontend on `python -m http.server`, backend on :8000).
export async function detectApiBase() {
  let saved = null;
  try { saved = localStorage.getItem("spiderly_api_base"); } catch { /* storage unavailable */ }
  if (saved || !location.protocol.startsWith("http")) return state.apiBase;
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 2500);
    const res = await fetch(`${location.origin}/api/status`, { signal: ctl.signal, cache: "no-store" });
    clearTimeout(timer);
    if (res.ok) { state.apiBase = location.origin; return state.apiBase; }
  } catch { /* no API on this origin */ }
  state.apiBase = LOCAL_API;
  return state.apiBase;
}
