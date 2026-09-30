import { detectApiBase } from "./api.js";
import { initNav } from "./nav.js";
import { initStatus } from "./status.js";
import { initSettings } from "./settings.js";
import { initScanForm } from "./scanForm.js";
import { initCancel } from "./live.js";
import { initPorts } from "./ports.js";
import { initGraph, initGraphControls } from "./graph.js";
import { initHistory } from "./history.js";

await detectApiBase(); // must run before anything reads state.apiBase

initNav();
initSettings();
initScanForm();
initCancel();
initPorts();
initGraphControls();
initHistory();
initGraph("—");
initStatus();
