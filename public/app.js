// SootSleuth frontend — upload, mode switch, live SSE log.

const $ = sel => document.querySelector(sel);
const state = { jobId: null, primary: null, files: [], es: null, hasOutput: false };

// ── Tool status chips ────────────────────────────────────────────────────────
async function loadTools() {
  try {
    const { tools, devices } = await (await fetch("/api/tools")).json();
    const chips = [
      ["java", tools.java], ["javac", tools.javac], ["Android SDK", tools.platforms],
      ["adb", tools.adb], ["zipalign", tools.zipalign], ["apksigner", tools.apksigner],
      ["jars", tools.jarLibsExist], ["injector", tools.injectorCompiled],
    ];
    $("#toolbar").innerHTML = chips.map(([n, on]) =>
      `<span class="chip ${on ? "on" : "off"}">${on ? "✓" : "✕"} ${n}</span>`).join("");
    const sel = $("#deviceSel");
    sel.innerHTML = `<option value="">(auto)</option>` +
      devices.map(d => `<option value="${d.serial}">${d.serial}</option>`).join("");
    $("#instrumentBtn").dataset.adb = tools.adb ? "1" : "0";
  } catch (e) { $("#toolbar").textContent = "tool check failed"; }
}
loadTools();

// ── Drag & drop / browse ─────────────────────────────────────────────────────
const drop = $("#drop"), input = $("#fileInput");
$("#browseBtn").onclick = () => input.click();
input.onchange = () => input.files.length && uploadFiles(input.files);
["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("drag"); }));
["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("drag"); }));
drop.addEventListener("drop", e => { if (e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files); });

async function uploadFiles(fileList) {
  const fd = new FormData();
  for (const f of fileList) fd.append("apk", f);
  $("#fileList").innerHTML = `<div class="f">Uploading…</div>`;
  try {
    const r = await fetch("/api/upload", { method: "POST", body: fd });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "upload failed");
    state.jobId = data.jobId; state.primary = data.primary; state.files = data.files;
    state.hasOutput = false;
    $("#fileList").innerHTML = data.files.map(f =>
      `<div class="f"><b>${f.name}</b> — ${(f.size / 1048576).toFixed(1)} MB${f.name === data.primary ? " (primary)" : ""}</div>`).join("");
    $("#modes").classList.remove("hidden");
    $("#logSection").classList.remove("hidden");
    $("#inspectResult").innerHTML = "";
    $("#downloads").innerHTML = "";
    $("#instrumentBtn").disabled = true;
    resetExplorer();
    openStream();
  } catch (e) {
    $("#fileList").innerHTML = `<div class="f err">${e.message}</div>`;
  }
}

// ── SSE stream ───────────────────────────────────────────────────────────────
function openStream() {
  if (state.es) state.es.close();
  const es = new EventSource(`/api/stream/${state.jobId}`);
  state.es = es;
  es.addEventListener("line", e => appendLog(JSON.parse(e.data)));
  es.addEventListener("done", e => onDone(JSON.parse(e.data)));
  es.onerror = () => {}; // server ends stream on done; ignore
}
function appendLog({ text, stream }) {
  const log = $("#log");
  const span = document.createElement("span");
  const cls = stream === "err" ? "err" : stream === "sys" ? "sys"
    : /\[OK\]|Signed|complete|SootInjection/.test(text) ? "ok" : "";
  if (cls) span.className = cls;
  span.textContent = text + "\n";
  log.appendChild(span);
  log.scrollTop = log.scrollHeight;
}
function onDone(payload) {
  appendLog({ text: `── job finished (${payload.kind || ""}${payload.ok === false ? ", FAILED" : ""}) ──`, stream: "sys" });
  if (payload.kind === "inject" && payload.ok) {
    state.hasOutput = true;
    if ($("#instrumentBtn").dataset.adb === "1") $("#instrumentBtn").disabled = false;
    renderDownloads(payload.apks || []);
  }
  // reopen a fresh stream so a follow-up action (instrument) still streams
  openStream();
}
function renderDownloads(apks) {
  $("#downloads").innerHTML = apks.length
    ? "<b>Injected APK(s):</b>" + apks.map(n =>
        `<a href="/api/download/${state.jobId}/${encodeURIComponent(n)}" download>⬇ ${n}</a>`).join("")
    : "";
}
$("#clearLog").onclick = () => $("#log").innerHTML = "";

// ── Mode tabs ────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(t => t.onclick = () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === t));
  document.querySelectorAll(".panel").forEach(p =>
    p.classList.toggle("active", p.dataset.panel === t.dataset.mode));
});

// ── Forensic ─────────────────────────────────────────────────────────────────
$("#inspectBtn").onclick = async () => {
  if (!state.jobId) return;
  $("#inspectResult").innerHTML = `<div class="hint">Inspecting…</div>`;
  try {
    const r = await fetch("/api/inspect", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jobId: state.jobId, file: state.primary }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    renderInspect(d);
  } catch (e) { $("#inspectResult").innerHTML = `<div class="f err">${e.message}</div>`; }
};
function renderInspect(d) {
  const m = d.meta || {};
  const el = document.createElement("div");
  el.innerHTML = `
    <div class="card"><h3>Package</h3><div class="kv">
      <span class="k">File</span><span>${d.file} (${(d.sizeBytes / 1048576).toFixed(1)} MB)</span>
      ${d.bundle ? `<span class="k">Bundle</span><span>${d.bundle.type.toUpperCase()} — base: ${d.bundle.baseApk}, ${d.bundle.splitCount} split(s)</span>` : ""}
      <span class="k">Package</span><span>${m.package || "—"}</span>
      <span class="k">Version</span><span>${m.versionName || "—"} (${m.versionCode || "—"})</span>
      <span class="k">App name</span><span>${m.appName || "—"}</span>
      <span class="k">Target SDK</span><span>${m.targetSdk || "—"}</span>
      <span class="k">DEX files</span><span>${d.dexCount}</span>
      <span class="k">Scan method</span><span>${d.method}</span>
    </div></div>
    <div class="card"><h3>Ad SDKs ${d.hasAds ? "" : "— none detected"}</h3>
      <div class="badges">${d.adSdks.map(s => `<span class="badge ad">${s}</span>`).join("") || '<span class="hint">none</span>'}</div>
    </div>
    <div class="card"><h3>Play Store traces</h3>
      <div class="badges">${d.playStoreTraces.map(s => `<span class="badge play">${s}</span>`).join("") || '<span class="hint">none</span>'}</div>
    </div>
    <div class="card"><h3>Permissions (${d.permissions.length})${d.permSource && d.permSource !== "none" ? ` · via ${d.permSource}` : ""}</h3>
      <div class="perm-list">${d.permissions.length
        ? d.permissions.map(p => {
            const short = p.replace(/^android\.permission\./, "");
            return `<span class="perm" title="${p}">${short}</span>`;
          }).join("")
        : "—"}</div>
    </div>`;
  $("#inspectResult").innerHTML = "";
  $("#inspectResult").appendChild(el);
}

// ── Forensic: Jimple + CFG explorer ───────────────────────────────────────────
const ex = { classes: [], className: null, methods: [], subsig: null };

function resetExplorer() {
  ex.classes = []; ex.className = null; ex.methods = []; ex.subsig = null;
  $("#explorerBody").classList.add("hidden");
  $("#classList").innerHTML = ""; $("#methodList").innerHTML = "";
  $("#classSearch").value = ""; $("#methodSearch").value = "";
  $("#methodSearch").disabled = true;
  $("#jimpleOut").textContent = "Pick a class (and optionally a method) to view Jimple.";
  $("#cfgWrap").innerHTML = `<div class="hint">Pick a method to render its control-flow graph.</div>`;
  $("#cgWrap").innerHTML = `<div class="hint">Whole-app call graph: methods are nodes, edges are calls. Scoped to the app's own package and capped for readability. Click <b>Render</b> (loads app classes first if needed).</div>`;
  $("#cgMeta").textContent = ""; $("#cgPkg").value = ""; $("#cgCap").value = "400";
  $("#explorerHint").textContent = "Decompile app classes to Soot's Jimple IR and view a method's control-flow graph.";
}

async function api(url, body) {
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jobId: state.jobId, file: state.primary, ...body }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || "request failed");
  return d;
}

$("#loadClassesBtn").onclick = async () => {
  if (!state.jobId) return;
  const hint = $("#explorerHint");
  hint.textContent = "Loading classes via Soot (first call warms up)…";
  $("#loadClassesBtn").disabled = true;
  try {
    const { classes } = await api("/api/classes");
    ex.classes = classes;
    $("#explorerBody").classList.remove("hidden");
    renderClassList("");
    hint.textContent = `${classes.length} app class(es).`;
  } catch (e) {
    hint.textContent = "Error: " + e.message;
  } finally { $("#loadClassesBtn").disabled = false; }
};

function renderClassList(filter) {
  const f = filter.toLowerCase();
  const list = ex.classes.filter(c => c.toLowerCase().includes(f)).slice(0, 2000);
  $("#classList").innerHTML = list.map(c =>
    `<li data-c="${c}" class="${c === ex.className ? "sel" : ""}">${c}</li>`).join("")
    || `<li class="hint">no match</li>`;
}
$("#classSearch").oninput = e => renderClassList(e.target.value);

$("#classList").onclick = async e => {
  const li = e.target.closest("li[data-c]");
  if (!li) return;
  ex.className = li.dataset.c; ex.subsig = null;
  renderClassList($("#classSearch").value);
  $("#methodSearch").disabled = false;
  $("#methodList").innerHTML = `<li class="hint">loading methods…</li>`;
  // Show whole-class Jimple immediately.
  loadJimple();
  try {
    const { methods } = await api("/api/methods", { className: ex.className });
    ex.methods = methods;
    renderMethodList("");
  } catch (err) { $("#methodList").innerHTML = `<li class="hint">${err.message}</li>`; }
};

function renderMethodList(filter) {
  const f = filter.toLowerCase();
  const list = ex.methods.filter(m => m.subsig.toLowerCase().includes(f));
  $("#methodList").innerHTML = list.map(m =>
    `<li data-s="${encodeURIComponent(m.subsig)}" title="${m.subsig}" class="${m.subsig === ex.subsig ? "sel" : ""}">${m.subsig}</li>`).join("")
    || `<li class="hint">no match</li>`;
}
$("#methodSearch").oninput = e => renderMethodList(e.target.value);

$("#methodList").onclick = e => {
  const li = e.target.closest("li[data-s]");
  if (!li) return;
  ex.subsig = decodeURIComponent(li.dataset.s);
  renderMethodList($("#methodSearch").value);
  const view = document.querySelector(".vtab.active").dataset.view;
  if (view === "cfg") loadCfg(); else loadJimple();
};

// View sub-tabs (Jimple / CFG / App call graph)
document.querySelectorAll(".vtab").forEach(t => t.onclick = () => {
  document.querySelectorAll(".vtab").forEach(x => x.classList.toggle("active", x === t));
  document.querySelectorAll(".view-pane").forEach(p =>
    p.classList.toggle("hidden", p.dataset.viewpane !== t.dataset.view));
  const v = t.dataset.view;
  if (v === "cfg") loadCfg();
  else if (v === "jimple") loadJimple();
  // callgraph is on-demand (heavy) — user clicks Render.
});

async function loadJimple() {
  if (!ex.className) return;
  const out = $("#jimpleOut");
  out.textContent = "loading…";
  try {
    const d = await api("/api/jimple", { className: ex.className, subsig: ex.subsig || undefined });
    out.textContent = d.jimple || "// (empty)";
  } catch (e) { out.textContent = "Error: " + e.message; }
}

async function loadCfg() {
  const wrap = $("#cfgWrap");
  if (!ex.className || !ex.subsig) { wrap.innerHTML = `<div class="hint">Pick a method to render its control-flow graph.</div>`; return; }
  wrap.innerHTML = `<div class="hint">building CFG…</div>`;
  try {
    const d = await api("/api/cfg", { className: ex.className, subsig: ex.subsig });
    if (!d.nodes || !d.nodes.length) { wrap.innerHTML = `<div class="hint">${d.note || "no control-flow graph (no body)"}</div>`; return; }
    wrap.innerHTML = "";
    wrap.appendChild(renderCfg(d));
  } catch (e) { wrap.innerHTML = `<div class="hint">Error: ${e.message}</div>`; }
}

// Simple layered layout: assign each node a depth (longest path from an entry
// in the DAG of fall/branch edges), lay depths out top→bottom, then draw an SVG
// with statement boxes and colored edges. Good enough for method-sized graphs.
function renderCfg(cfg) {
  const nodes = cfg.nodes, edges = cfg.edges;
  const byId = new Map(nodes.map(n => [n.id, n]));
  const succ = new Map(nodes.map(n => [n.id, []]));
  const indeg = new Map(nodes.map(n => [n.id, 0]));
  for (const e of edges) {
    if (!succ.has(e.from) || !byId.has(e.to)) continue;
    succ.get(e.from).push(e.to);
    indeg.set(e.to, indeg.get(e.to) + 1);
  }
  // BFS depth from nodes with indeg 0 (fallback: node 0), ignoring back-edges.
  const depth = new Map();
  const roots = nodes.filter(n => indeg.get(n.id) === 0).map(n => n.id);
  const queue = roots.length ? roots.slice() : [nodes[0].id];
  queue.forEach(id => depth.set(id, 0));
  const seen = new Set(queue);
  // Iterative relaxation over edges (few nodes; keep it simple & robust to cycles).
  for (let pass = 0; pass < nodes.length; pass++) {
    let changed = false;
    for (const e of edges) {
      if (!depth.has(e.from)) continue;
      const nd = depth.get(e.from) + 1;
      if (!depth.has(e.to) || nd > depth.get(e.to)) {
        // cap to avoid runaway on cycles
        if (nd <= nodes.length) { depth.set(e.to, nd); changed = true; }
      }
    }
    if (!changed) break;
  }
  nodes.forEach(n => { if (!depth.has(n.id)) depth.set(n.id, 0); });

  // Group by depth → rows; order within a row by id for stability.
  const rows = new Map();
  for (const n of nodes) {
    const d = depth.get(n.id);
    if (!rows.has(d)) rows.set(d, []);
    rows.get(d).push(n);
  }
  const depths = [...rows.keys()].sort((a, b) => a - b);

  // Layout constants.
  const BW = 320, ROWH = 78, PADX = 24, PADY = 24, GAPX = 24;
  const pos = new Map();
  let maxCols = 0;
  depths.forEach((d, r) => {
    const row = rows.get(d).sort((a, b) => a.id - b.id);
    maxCols = Math.max(maxCols, row.length);
    row.forEach((n, c) => pos.set(n.id, {
      x: PADX + c * (BW + GAPX),
      y: PADY + r * ROWH,
      row: r, col: c,
    }));
  });
  const width = PADX * 2 + maxCols * BW + (maxCols - 1) * GAPX;
  const height = PADY * 2 + depths.length * ROWH;

  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("width", width);
  svg.setAttribute("height", height);
  svg.setAttribute("class", "cfg-svg");

  const EDGE_COLOR = { fall: "#8a8f98", branch: "#3fb950", goto: "#a371f7", switch: "#d29922", exc: "#f85149" };
  // arrow markers per color
  const defs = document.createElementNS(NS, "defs");
  for (const [k, col] of Object.entries(EDGE_COLOR)) {
    const m = document.createElementNS(NS, "marker");
    m.setAttribute("id", "arw-" + k);
    m.setAttribute("markerWidth", "8"); m.setAttribute("markerHeight", "8");
    m.setAttribute("refX", "7"); m.setAttribute("refY", "3");
    m.setAttribute("orient", "auto"); m.setAttribute("markerUnits", "userSpaceOnUse");
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", "M0,0 L7,3 L0,6 Z"); p.setAttribute("fill", col);
    m.appendChild(p); defs.appendChild(m);
  }
  svg.appendChild(defs);

  const BH = 46;
  // Edges first (under boxes).
  for (const e of edges) {
    const a = pos.get(e.from), b = pos.get(e.to);
    if (!a || !b) continue;
    const col = EDGE_COLOR[e.kind] || EDGE_COLOR.fall;
    const backEdge = b.y <= a.y;
    const x1 = a.x + BW / 2, y1 = a.y + BH;
    const x2 = b.x + BW / 2, y2 = b.y;
    const path = document.createElementNS(NS, "path");
    let d;
    if (backEdge) {
      // route back-edges out to the right so they don't overlap boxes
      const off = Math.min(width - (a.x + BW), 60) + 30;
      const mx = Math.max(x1, x2) + off;
      d = `M${x1},${y1 - BH / 2} C${mx},${y1} ${mx},${y2} ${x2},${y2 + BH / 2}`;
    } else {
      const my = (y1 + y2) / 2;
      d = `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`;
    }
    path.setAttribute("d", d);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", col);
    path.setAttribute("stroke-width", backEdge ? "1.5" : "1.8");
    if (backEdge) path.setAttribute("stroke-dasharray", "4,3");
    path.setAttribute("marker-end", `url(#arw-${e.kind in EDGE_COLOR ? e.kind : "fall"})`);
    svg.appendChild(path);
  }

  // Boxes.
  const KIND_CLASS = { branch: "n-branch", switch: "n-switch", goto: "n-goto", throw: "n-throw", return: "n-return" };
  for (const n of nodes) {
    const p = pos.get(n.id);
    const g = document.createElementNS(NS, "g");
    g.setAttribute("transform", `translate(${p.x},${p.y})`);
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("width", BW); rect.setAttribute("height", BH);
    rect.setAttribute("rx", "6");
    rect.setAttribute("class", "cfg-node " + (KIND_CLASS[n.kind] || "n-stmt"));
    g.appendChild(rect);
    const txt = document.createElementNS(NS, "text");
    txt.setAttribute("x", "10"); txt.setAttribute("y", "27");
    txt.setAttribute("class", "cfg-text");
    const label = `${n.id}: ${n.text}`;
    txt.textContent = label.length > 46 ? label.slice(0, 45) + "…" : label;
    const title = document.createElementNS(NS, "title");
    title.textContent = n.text;
    g.appendChild(txt); g.appendChild(title);
    svg.appendChild(g);
  }
  return svg;
}

// ── App call graph ─────────────────────────────────────────────────────────────
$("#cgRenderBtn").onclick = loadCallGraph;
async function loadCallGraph() {
  if (!state.jobId) return;
  const wrap = $("#cgWrap"), meta = $("#cgMeta");
  const pkgPrefix = $("#cgPkg").value.trim();
  const maxNodes = parseInt($("#cgCap").value, 10) || 400;
  wrap.innerHTML = `<div class="hint">building call graph via Soot (first call warms up)…</div>`;
  meta.textContent = "";
  $("#cgRenderBtn").disabled = true;
  try {
    const d = await api("/api/callgraph", { pkgPrefix, maxNodes });
    if (!d.nodes || !d.nodes.length) { wrap.innerHTML = `<div class="hint">no methods in scope "${d.scope}".</div>`; return; }
    // Auto-fill the detected package so the user sees/can-edit the scope.
    if (!pkgPrefix && d.basePackage) $("#cgPkg").value = d.basePackage;
    meta.innerHTML =
      `scope <b>${d.scope}</b> · ${d.nodeCount} methods · ${d.edgeCount} calls`
      + (d.truncated ? ` · <span class="cg-trunc">truncated to ${d.maxNodes} — narrow the package or raise max nodes</span>` : "");
    wrap.innerHTML = "";
    wrap.appendChild(renderCallGraph(d));
  } catch (e) { wrap.innerHTML = `<div class="hint">Error: ${e.message}</div>`; }
  finally { $("#cgRenderBtn").disabled = false; }
}

// Layered layout for a directed (possibly cyclic) call graph: assign levels by
// longest-path relaxation ignoring back-edges, pack each level into a row, draw
// an SVG with pan (drag) + zoom (wheel). Node click shows the method's Jimple.
function renderCallGraph(cg) {
  const nodes = cg.nodes, edges = cg.edges;
  const byId = new Map(nodes.map(n => [n.id, n]));
  const indeg = new Map(nodes.map(n => [n.id, 0]));
  for (const e of edges) if (byId.has(e.to)) indeg.set(e.to, indeg.get(e.to) + 1);

  // Longest-path leveling, capped to survive cycles.
  const level = new Map(nodes.map(n => [n.id, 0]));
  for (let pass = 0; pass < Math.min(nodes.length, 60); pass++) {
    let changed = false;
    for (const e of edges) {
      if (!level.has(e.from) || !level.has(e.to)) continue;
      const nl = level.get(e.from) + 1;
      if (nl > level.get(e.to) && nl <= nodes.length) { level.set(e.to, nl); changed = true; }
    }
    if (!changed) break;
  }

  // Rows by level.
  const rows = new Map();
  for (const n of nodes) {
    const l = level.get(n.id);
    if (!rows.has(l)) rows.set(l, []);
    rows.get(l).push(n);
  }
  const levels = [...rows.keys()].sort((a, b) => a - b);

  const BW = 210, BH = 34, GAPX = 18, ROWH = 74, PADX = 24, PADY = 24;
  const pos = new Map();
  let maxCols = 0;
  levels.forEach((l, r) => {
    const row = rows.get(l).sort((a, b) => a.label.localeCompare(b.label));
    maxCols = Math.max(maxCols, row.length);
    row.forEach((n, c) => pos.set(n.id, { x: PADX + c * (BW + GAPX), y: PADY + r * ROWH }));
  });
  const width = PADX * 2 + Math.max(1, maxCols) * BW + (maxCols - 1) * GAPX;
  const height = PADY * 2 + levels.length * ROWH;

  const NS = "http://www.w3.org/2000/svg";
  const container = document.createElement("div");
  container.className = "cg-viewport";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("width", width);
  svg.setAttribute("height", height);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("class", "cg-svg");

  const defs = document.createElementNS(NS, "defs");
  const mk = document.createElementNS(NS, "marker");
  mk.setAttribute("id", "cg-arrow");
  mk.setAttribute("markerWidth", "7"); mk.setAttribute("markerHeight", "7");
  mk.setAttribute("refX", "6"); mk.setAttribute("refY", "2.5");
  mk.setAttribute("orient", "auto"); mk.setAttribute("markerUnits", "userSpaceOnUse");
  const mp = document.createElementNS(NS, "path");
  mp.setAttribute("d", "M0,0 L6,2.5 L0,5 Z"); mp.setAttribute("fill", "#5b6472");
  mk.appendChild(mp); defs.appendChild(mk); svg.appendChild(defs);

  // Edges.
  for (const e of edges) {
    const a = pos.get(e.from), b = pos.get(e.to);
    if (!a || !b) continue;
    const back = b.y <= a.y;
    const x1 = a.x + BW / 2, y1 = a.y + BH, x2 = b.x + BW / 2, y2 = b.y;
    const path = document.createElementNS(NS, "path");
    let d;
    if (back) {
      const mx = Math.max(x1, x2) + 46;
      d = `M${x1},${a.y + BH / 2} C${mx},${y1} ${mx},${y2} ${x2},${b.y + BH / 2}`;
    } else {
      const my = (y1 + y2) / 2;
      d = `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`;
    }
    path.setAttribute("d", d);
    path.setAttribute("class", "cg-edge" + (back ? " back" : ""));
    path.setAttribute("marker-end", "url(#cg-arrow)");
    svg.appendChild(path);
  }

  // Nodes.
  for (const n of nodes) {
    const p = pos.get(n.id);
    const g = document.createElementNS(NS, "g");
    g.setAttribute("transform", `translate(${p.x},${p.y})`);
    g.setAttribute("class", "cg-node k-" + (n.kind || "method"));
    g.style.cursor = "pointer";
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("width", BW); rect.setAttribute("height", BH); rect.setAttribute("rx", "6");
    g.appendChild(rect);
    const txt = document.createElementNS(NS, "text");
    txt.setAttribute("x", "9"); txt.setAttribute("y", "22"); txt.setAttribute("class", "cg-ntext");
    txt.textContent = n.label.length > 30 ? n.label.slice(0, 29) + "…" : n.label;
    const title = document.createElementNS(NS, "title");
    title.textContent = `${n.cls}: ${n.sub}\n(click to view Jimple)`;
    g.appendChild(txt); g.appendChild(title);
    // Click a node → jump to its method's Jimple.
    g.onclick = () => openMethodJimple(n.cls, n.sub);
    svg.appendChild(g);
  }

  container.appendChild(svg);
  attachPanZoom(container, svg, width, height);
  return container;
}

// Selecting a call-graph node loads that class+method into the Jimple view.
async function openMethodJimple(cls, sub) {
  ex.className = cls; ex.subsig = sub;
  // switch to the Jimple tab
  document.querySelectorAll(".vtab").forEach(x => x.classList.toggle("active", x.dataset.view === "jimple"));
  document.querySelectorAll(".view-pane").forEach(p => p.classList.toggle("hidden", p.dataset.viewpane !== "jimple"));
  // reflect in the class picker if present
  if (ex.classes.length) { $("#classSearch").value = cls; renderClassList(cls); }
  loadJimple();
}

// Drag to pan, wheel to zoom, over an SVG inside a viewport div.
function attachPanZoom(viewport, svg, w, h) {
  let scale = 1, tx = 0, ty = 0, dragging = false, sx = 0, sy = 0;
  const apply = () => svg.style.transform = `translate(${tx}px,${ty}px) scale(${scale})`;
  svg.style.transformOrigin = "0 0";
  viewport.addEventListener("wheel", e => {
    e.preventDefault();
    const f = e.deltaY < 0 ? 1.1 : 1 / 1.1;
    const rect = viewport.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    // zoom toward cursor
    tx = mx - (mx - tx) * f; ty = my - (my - ty) * f;
    scale = Math.max(0.1, Math.min(4, scale * f));
    apply();
  }, { passive: false });
  viewport.addEventListener("mousedown", e => { dragging = true; sx = e.clientX - tx; sy = e.clientY - ty; viewport.classList.add("grabbing"); });
  window.addEventListener("mousemove", e => { if (!dragging) return; tx = e.clientX - sx; ty = e.clientY - sy; apply(); });
  window.addEventListener("mouseup", () => { dragging = false; viewport.classList.remove("grabbing"); });
  apply();
}

// ── Hacking ──────────────────────────────────────────────────────────────────
const patternsInput = $("#patterns");
document.querySelectorAll('input[name="scope"]').forEach(r => r.onchange = () => {
  const custom = document.querySelector('input[name="scope"]:checked').value === "custom";
  patternsInput.disabled = !custom;
  $("#scopeHint").textContent = custom
    ? "Tip: to reach AdMob, use com.google.android.gms.ads.* — custom filters bypass the inject-all exclude list."
    : "";
});

$("#injectBtn").onclick = async () => {
  if (!state.jobId) return;
  const custom = document.querySelector('input[name="scope"]:checked').value === "custom";
  const patterns = custom ? patternsInput.value.split(",").map(s => s.trim()).filter(Boolean) : [];
  appendLog({ text: "▶ Starting injection…", stream: "sys" });
  await fetch("/api/inject", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jobId: state.jobId, file: state.primary, injectAll: !custom, patterns }),
  });
};

$("#instrumentBtn").onclick = async () => {
  if (!state.jobId || !state.hasOutput) return;
  const device = $("#deviceSel").value;
  const durationMs = (parseInt($("#duration").value, 10) || 30) * 1000;
  appendLog({ text: "▶ Installing on device & capturing logcat…", stream: "sys" });
  await fetch("/api/instrument", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jobId: state.jobId, device, durationMs }),
  });
};
