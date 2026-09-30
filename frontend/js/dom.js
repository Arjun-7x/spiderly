// Tiny DOM helpers shared by every module.
export const $ = (id) => document.getElementById(id);

export function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

export function showToast(message, type = "info", duration = 4200) {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  $("toastStack").appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    setTimeout(() => el.remove(), 200);
  }, duration);
}

export function setDot(dotId, ok, pending = false) {
  const dot = $(dotId);
  if (!dot) return;
  dot.classList.remove("offline", "pending");
  if (pending) dot.classList.add("pending");
  else if (!ok) dot.classList.add("offline");
}
