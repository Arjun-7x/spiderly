// Single shared, mutable UI state. Modules import and mutate this object.
const stored = (k) => { try { return localStorage.getItem(k); } catch { return null; } };

export const state = {
  // When served by the backend (Docker, Render, :8000) the API lives on the same origin.
  // detectApiBase() confirms that at startup and falls back to localhost otherwise.
  apiBase: stored("spiderly_api_base")
    || (location.protocol.startsWith("http") ? location.origin : "http://127.0.0.1:8000"),
  apiKey: stored("spiderly_api_key") || "",
  currentScanId: null,
  currentScanStatus: null, // 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted'
  ws: null,
  wsReconnectAttempts: 0,
  wsReconnectTimer: null,
  openPorts: [],        // {port, service, version, banner}
  findings: [],
  portsSearch: "",
  portsSort: "port-asc",
  expandedPorts: new Set(),
  historySearch: "",
  historyCache: [],
  prefersReducedMotion: !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches),
};
