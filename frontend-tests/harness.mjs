// Boots the real frontend (index.html + js/main.js) inside jsdom with a fake
// backend (fetch) and a fake WebSocket, so UI behaviour can be tested headlessly.
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { JSDOM } from "jsdom";

const FRONTEND = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../frontend");

export class FakeWebSocket {
  static instances = [];
  constructor(url) { this.url = url; this.closed = false; FakeWebSocket.instances.push(this); }
  close() { if (this.closed) return; this.closed = true; this.onclose && this.onclose({}); }
  // test helpers
  open() { this.onopen && this.onopen({}); }
  push(event) { this.onmessage && this.onmessage({ data: JSON.stringify(event) }); }
  serverClose() { this.close(); }
}

export async function boot({ url = "http://localhost:8000/", routes = {}, storage = {} } = {}) {
  const dom = new JSDOM(readFileSync(path.join(FRONTEND, "index.html"), "utf8"), { url, pretendToBeVisual: true });
  const { window } = dom;
  const calls = [];
  const store = new Map(Object.entries(storage));
  const localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };

  const fakeFetch = async (u, opts = {}) => {
    const pathname = new URL(u).pathname;
    const method = (opts.method || "GET").toUpperCase();
    calls.push({ url: u, path: pathname, method, headers: opts.headers || {}, body: opts.body ? JSON.parse(opts.body) : undefined });
    const bare = u.split("?")[0];
    const handler = routes[`${method} ${bare}`] || routes[bare] || routes[`${method} ${pathname}`] || routes[pathname];
    const out = handler ? await (typeof handler === "function" ? handler(opts) : handler) : { status: 404, body: { detail: "no route" } };
    const status = out.status ?? 200;
    return { ok: status >= 200 && status < 300, status, json: async () => out.body };
  };

  const define = (k, v) => Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
  define("window", window);
  define("document", window.document);
  define("location", window.location);
  define("navigator", { clipboard: { writeText: async () => {} } });
  define("localStorage", localStorage);
  define("fetch", fakeFetch);
  define("WebSocket", FakeWebSocket);
  define("confirm", () => true);
  define("HTMLElement", window.HTMLElement);
  FakeWebSocket.instances.length = 0;

  // NOTE: only main.js is cache-busted; its imports stay cached, so boot() once per test file
  // (node --test runs each file in its own process).
  const bust = "";
  const main = await import(pathToFileURL(path.join(FRONTEND, "js/main.js")).href + bust).catch((e) => { throw e; });
  return { window, document: window.document, calls, store, $: (id) => window.document.getElementById(id), ws: () => FakeWebSocket.instances.at(-1), main };
}

export const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
