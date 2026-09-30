import { $ } from "./dom.js";

// Pages register hooks instead of nav importing them (avoids import cycles).
const hooks = {};
export function onPageShow(name, fn) { hooks[name] = fn; }

export function showPage(name) {
  document.querySelectorAll(".nav-item").forEach((el) => el.classList.toggle("active", el.dataset.page === name));
  document.querySelectorAll(".page").forEach((el) => el.classList.remove("active"));
  $(`page-${name}`).classList.add("active");
  if (hooks[name]) hooks[name]();
}

export function initNav() {
  document.querySelectorAll(".nav-item").forEach((el) => el.addEventListener("click", () => showPage(el.dataset.page)));
  $("goScannerBtn").addEventListener("click", () => showPage("scanner"));
}
