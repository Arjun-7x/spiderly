import { state } from "./state.js";
import { $, showToast } from "./dom.js";
import { pingBackend } from "./status.js";

export function initSettings() {
  $("apiBaseInput").value = state.apiBase;
  $("apiKeyInput").value = state.apiKey;
  $("saveApiBaseBtn").addEventListener("click", () => {
    state.apiBase = $("apiBaseInput").value.trim().replace(/\/$/, "");
    state.apiKey = $("apiKeyInput").value.trim();
    try {
      localStorage.setItem("spiderly_api_base", state.apiBase);
      localStorage.setItem("spiderly_api_key", state.apiKey);
    } catch { /* storage unavailable: keep in memory for this session */ }
    pingBackend();
    showToast("Settings saved.", "success");
  });
}
