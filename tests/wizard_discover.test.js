#!/usr/bin/env node
/**
 * Browser-faithful regression test for the wizard "Discovered routers" dropdown.
 *
 * Why this exists: a prior version had `getElementById("discovered-status")` in the
 * JS while the HTML markup used `id="discover-status"`. In a real browser that call
 * returns null and `status.innerHTML = ...` throws, so the dropdown wrapper (which
 * starts hidden) was never revealed — "Load scan" looked broken. Synthetic tests with
 * auto-creating DOM stubs missed it because they never return null.
 *
 * This harness models a real browser: getElementById returns null for any id that is
 * NOT actually present in the HTML markup. If the JS references a non-existent element,
 * the dereference throws and the test fails.
 *
 * Run:  node tests/wizard_discover.test.js
 */
const fs = require("fs");
const path = require("path");

const HTML_PATH = path.join(__dirname, "..", "docs", "wizard.html");
const html = fs.readFileSync(HTML_PATH, "utf8");
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

// --- Collect the REAL element ids from the HTML markup (self-syncing) ---
const realIds = new Set();
for (const m of html.matchAll(/\sid="([^"]+)"/g)) realIds.add(m[1]);

function extract(src, name) {
  const start = src.indexOf("function " + name + "(");
  if (start < 0) throw new Error("function " + name + " not found in wizard.html");
  let i = src.indexOf("{", start), depth = 0, end = i;
  for (; end < src.length; end++) {
    if (src[end] === "{") depth++;
    else if (src[end] === "}") { depth--; if (depth === 0) { end++; break; } }
  }
  return src.slice(start, end);
}

// --- Browser-faithful DOM stub ---
// getElementById returns null for ids NOT in the markup, like a real browser.
function makeEl(id) {
  const kids = [];
  return {
    id,
    style: { display: "" },
    _value: "", _innerHTML: "", _text: "",
    get value() { return this._value; },
    set value(v) { this._value = String(v); },
    get innerHTML() { return this._innerHTML; },
    set innerHTML(v) { this._innerHTML = String(v); }, // browser also rebuilds children
    get textContent() { return this._text; },
    set textContent(v) { this._text = String(v); },
    get children() { return kids; },
    addEventListener() {},
    appendChild(c) { kids.push(c); return c; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    options: [],
  };
}
const liveEls = {};
const document = {
  getElementById(id) {
    if (!realIds.has(id)) return null; // ← the whole point
    if (!liveEls[id]) liveEls[id] = makeEl(id);
    return liveEls[id];
  },
  createElement(tag) { return makeEl(tag); },
};
const window = {};
const navigator = { clipboard: { writeText: async () => {} } };
const history = { replaceState() {} };
const location = { search: "", pathname: "/wizard.html" };

// Sandbox-ish scope for the extracted functions.
let BUNDLE = { models: [
  { id: "zyxel-gs1900-8hp-v1", vendor: "ZyXEL", description: "GS1900-8HP v1" },
  { id: "glinet-gl-mt3000", vendor: "GL.iNet", description: "Beryl AX MT3000" },
  { id: "comfast-cf-wr632ax", vendor: "COMFAST", description: "CF-WR632AX" },
]};
let discoveredRouters = [];
// escapeHtml, loadDiscovered, pickDiscovered, matchDiscoveredModel are defined
// by eval() below (function declarations leak into this scope in sloppy mode).

eval([
  extract(script, "escapeHtml"),
  extract(script, "loadDiscovered"),
  extract(script, "pickDiscovered"),
  extract(script, "matchDiscoveredModel"),
].join("\n\n"));

// --- Tiny test runner ---
let passed = 0, failed = 0;
function check(cond, msg) {
  if (cond) { passed++; }
  else { failed++; console.log("  FAIL: " + msg); }
}

const SAMPLE = [
  { ip: "192.168.1.1", mac: "d8:5d:84:11:22:33", vendor: "ZyXEL", open_ports: [22, 80],
    likely_router: true, router_score: 100, model_hints: ["zyxel-gs1900-8hp-v1"] },
  { ip: "192.168.1.2", mac: "94:83:c4:aa:bb:cc", vendor: "GL.iNet", open_ports: [22, 80, 8080],
    likely_router: true, router_score: 95 },
  { ip: "192.168.1.99", mac: "aa:bb:cc:dd:ee:ff", vendor: "Unknown Inc", open_ports: [],
    likely_router: false, router_score: 0 },
];

// Test 1: valid scan → dropdown populated, sorted by score, wrapper revealed, status set.
(function t1() {
  // reset live els between tests
  for (const k of Object.keys(liveEls)) delete liveEls[k];
  document.getElementById("discover-json").value = JSON.stringify(SAMPLE);
  let threw = null;
  try { loadDiscovered(); } catch (e) { threw = e; }
  const sel = document.getElementById("discovered-select");
  const status = document.getElementById("discover-status");
  const wrap = document.getElementById("discover-select-wrap");
  check(!threw, "loadDiscovered(3 routers) must not throw (got: " + (threw && threw.message) + ")");
  check(discoveredRouters.length === 3, "discoveredRouters has 3 entries");
  check(sel && sel.children.length === 3, "select has 3 <option> children (got " + (sel && sel.children.length) + ")");
  check(sel && sel.children[0] && sel.children[0].textContent.includes("192.168.1.1"),
        "first option is the highest-score router (192.168.1.1)");
  check(status && /Loaded/.test(status.innerHTML), "status shows 'Loaded N host(s)'");
  check(wrap && wrap.style.display === "block", "wrapper revealed (display:block) — the bug that hid the dropdown");
})();

// Test 2: invalid JSON → friendly error, no throw, wrapper hidden.
(function t2() {
  for (const k of Object.keys(liveEls)) delete liveEls[k];
  document.getElementById("discover-json").value = "not json {{{";
  let threw = null;
  try { loadDiscovered(); } catch (e) { threw = e; }
  const status = document.getElementById("discover-status");
  const wrap = document.getElementById("discover-select-wrap");
  check(!threw, "invalid JSON must not throw");
  check(status && /Invalid JSON/i.test(status.innerHTML), "status shows 'Invalid JSON'");
  check(wrap && wrap.style.display !== "block", "wrapper stays hidden on bad JSON");
})();

// Test 3: single object (not array) tolerated.
(function t3() {
  for (const k of Object.keys(liveEls)) delete liveEls[k];
  document.getElementById("discover-json").value = JSON.stringify(SAMPLE[0]);
  let threw = null;
  try { loadDiscovered(); } catch (e) { threw = e; }
  const sel = document.getElementById("discovered-select");
  check(!threw, "single object must not throw");
  check(sel && sel.children.length === 1, "single object → 1 option (got " + (sel && sel.children.length) + ")");
})();

// Test 4: empty array → 'No hosts', no throw.
(function t4() {
  for (const k of Object.keys(liveEls)) delete liveEls[k];
  document.getElementById("discover-json").value = "[]";
  let threw = null;
  try { loadDiscovered(); } catch (e) { threw = e; }
  const status = document.getElementById("discover-status");
  check(!threw, "empty array must not throw");
  check(status && /No hosts/i.test(status.innerHTML), "status shows 'No hosts'");
})();

// Test 5: matchDiscoveredModel — hint match, vendor match, no match.
(function t5() {
  check(matchDiscoveredModel(SAMPLE[0]) && matchDiscoveredModel(SAMPLE[0]).id === "zyxel-gs1900-8hp-v1",
        "model_hints match resolves to bundle model");
  check(matchDiscoveredModel(SAMPLE[1]) && matchDiscoveredModel(SAMPLE[1]).id === "glinet-gl-mt3000",
        "vendor token match resolves to bundle model");
  check(matchDiscoveredModel(SAMPLE[2]) === null, "unknown vendor → null");
})();

// Test 6: pickDiscovered writes detail + triggers selectModel autofill.
(function t6() {
  for (const k of Object.keys(liveEls)) delete liveEls[k];
  document.getElementById("discover-json").value = JSON.stringify(SAMPLE);
  loadDiscovered();
  let picked = null;
  window.selectModel = (id) => { picked = id; };
  let threw = null;
  try { pickDiscovered(0); } catch (e) { threw = e; }
  const detail = document.getElementById("discovered-detail");
  check(!threw, "pickDiscovered(0) must not throw");
  check(detail && /192\.168\.1\.1/.test(detail.innerHTML), "detail shows the picked IP");
  check(picked === "zyxel-gs1900-8hp-v1", "selectModel auto-filled from model_hints");
})();

// Test 7: every getElementById used by the discover JS exists in the markup
// (static guard against the class of bug this test was written for).
(function t7() {
  const calls = [...script.matchAll(/getElementById\("([^"]+)"\)/g)].map(m => m[1]);
  const missing = calls.filter(id => !realIds.has(id));
  check(missing.length === 0,
        "every JS getElementById target exists in HTML markup (missing: " + missing.join(", ") + ")");
})();

console.log(`\n${failed === 0 ? "PASS" : "FAIL"}: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
