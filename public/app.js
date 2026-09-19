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
