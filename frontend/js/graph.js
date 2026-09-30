import { state } from "./state.js";
import { $, escapeHtml, showToast } from "./dom.js";

let nodes = [];
let edges = [];
const base = { w: 500, h: 420 };
const view = { x: 0, y: 0, w: base.w, h: base.h };

function applyViewBox() {
  $("networkSvg").setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
}

function zoom(factor) {
  const newW = Math.max(150, Math.min(base.w * 3, view.w * factor));
  const newH = Math.max(126, Math.min(base.h * 3, view.h * factor));
  const cx = view.x + view.w / 2, cy = view.y + view.h / 2;
  view.w = newW; view.h = newH; view.x = cx - newW / 2; view.y = cy - newH / 2;
  applyViewBox();
}

function resetView() {
  view.x = 0; view.y = 0; view.w = base.w; view.h = base.h;
  applyViewBox();
}

export function initGraph(target) {
  nodes = [{ id: "target", label: target, kind: "target", x: 250, y: 210 }];
  edges = [];
  resetView();
  renderGraph();
}

export function addGraphHost(address, reachable) {
  nodes[0].label = address;
  nodes[0].sub = reachable ? "reachable" : "no response to probes";
  renderGraph();
}

export function addGraphPort(port, service) {
  const id = `port:${port}`;
  if (nodes.find((n) => n.id === id)) return;
  const rad = (((nodes.length * 47) % 360) * Math.PI) / 180;
  const radius = 140 + (nodes.length % 3) * 25;
  nodes.push({ id, label: `${port}`, sub: service, kind: "port", x: 250 + Math.cos(rad) * radius, y: 210 + Math.sin(rad) * radius });
  edges.push({ from: "target", to: id });
  renderGraph();
}

function renderGraph() {
  const svg = $("networkSvg");
  applyViewBox();
  let html = "";
  for (const e of edges) {
    const a = nodes.find((n) => n.id === e.from), b = nodes.find((n) => n.id === e.to);
    if (!a || !b) continue;
    html += `<line class="edge-line" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"></line>`;
    if (!state.prefersReducedMotion) {
      html += `<circle class="pulse" r="2.5"><animateMotion dur="1.6s" repeatCount="indefinite" path="M${a.x},${a.y} L${b.x},${b.y}"/></circle>`;
    }
  }
  for (const n of nodes) {
    const color = n.kind === "target" ? "#35e6ff" : "#8a7bff";
    const r = n.kind === "target" ? 16 : 10;
    html += `<circle class="node-circle" data-node-id="${escapeHtml(n.id)}" cx="${n.x}" cy="${n.y}" r="${r}" fill="${color}" opacity="0.85">
      <title>${escapeHtml(n.label)}${n.sub ? " — " + escapeHtml(n.sub) : ""}</title></circle>`;
    html += `<text class="node-label" x="${n.x}" y="${n.y + r + 12}" text-anchor="middle">${escapeHtml(n.label)}</text>`;
  }
  svg.innerHTML = html;
  svg.querySelectorAll(".node-circle").forEach((circle) => {
    circle.addEventListener("click", (e) => {
      e.stopPropagation();
      const node = nodes.find((n) => n.id === circle.dataset.nodeId);
      if (!node) return;
      showToast(node.kind === "target" ? `Target host: ${node.label}` : `Port ${node.label} — ${node.sub || "Unknown service"}`, "info", 3000);
    });
  });
}

export function initGraphControls() {
  $("graphZoomIn").addEventListener("click", () => zoom(0.8));
  $("graphZoomOut").addEventListener("click", () => zoom(1.25));
  $("graphReset").addEventListener("click", resetView);

  const svg = $("networkSvg");
  let dragging = false, last = { x: 0, y: 0 };
  svg.addEventListener("wheel", (e) => { e.preventDefault(); zoom(e.deltaY > 0 ? 1.1 : 0.9); }, { passive: false });
  svg.addEventListener("pointerdown", (e) => { dragging = true; svg.classList.add("panning"); last = { x: e.clientX, y: e.clientY }; });
  window.addEventListener("pointermove", (e) => {
    if (!dragging) return;
    const rect = svg.getBoundingClientRect();
    view.x -= (e.clientX - last.x) * (view.w / rect.width);
    view.y -= (e.clientY - last.y) * (view.h / rect.height);
    last = { x: e.clientX, y: e.clientY };
    applyViewBox();
  });
  window.addEventListener("pointerup", () => { dragging = false; svg.classList.remove("panning"); });
}
