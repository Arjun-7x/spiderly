import test from "node:test";
import assert from "node:assert/strict";
import { boot, tick } from "./harness.mjs";

// Frontend on a static dev server (:5500) with no API on that origin -> fall back to local backend.
test("static dev server without API on its origin falls back to 127.0.0.1:8000", async () => {
  const app = await boot({
    url: "http://localhost:5500/",
    routes: { "http://127.0.0.1:8000/api/status": { body: { version: "0.3.0", database: "connected" } } },
  });
  await tick(30);
  assert.equal(app.$("apiBaseInput").value, "http://127.0.0.1:8000");
  process.exit(0);
});
