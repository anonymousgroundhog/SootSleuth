#!/usr/bin/env node
/**
 * SootSleuth — web server
 *
 * Two modes over one uploaded APK:
 *   FORENSIC — static inspection (ad SDKs, Play traces, manifest, metadata)
 *   HACKING  — Soot log injection (+ optional on-device instrumentation)
 *
 * Long-running jobs (inject/instrument) stream their output to the browser over
 * Server-Sent Events keyed by a jobId. Cross-platform: pure Node + a JDK; the
 * Android SDK (adb/build-tools) is optional and features degrade gracefully.
 */

const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const { checkTools, UPLOADS_DIR, OUTPUT_DIR } = require("./lib/tools");
const { inspectApk } = require("./lib/inspector");
const jimpleLib = require("./lib/jimple");
const { inject } = require("./lib/injector");
const { instrument, listDevices } = require("./lib/instrument");
const bundleLib = require("./lib/bundle");

const PORT = process.env.PORT || 4700;
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

for (const d of [UPLOADS_DIR, OUTPUT_DIR]) fs.mkdirSync(d, { recursive: true });

// ── Upload handling ────────────────────────────────────────────────────────
// Each upload gets its own subdir under uploads/<jobId>/ so split APKs and the
// injected output can live side by side and be cleaned up as a unit.
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const jobId = req.jobId || (req.jobId = crypto.randomBytes(6).toString("hex"));
    const dir = path.join(UPLOADS_DIR, jobId);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, sanitize(file.originalname)),
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB
  fileFilter: (req, file, cb) => {
    const ok = /\.(apk|xapk|apks)$/i.test(file.originalname);
    cb(ok ? null : new Error("Only .apk/.apks/.xapk files are accepted"), ok);
  },
});

function sanitize(name) { return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, "_"); }

// ── SSE job registry ─────────────────────────────────────────────────────────
// A job holds a buffered line log plus the set of currently-attached SSE
// clients. Buffering lets a client that connects slightly after a job starts
// still receive every line from the beginning.
const jobs = new Map(); // jobId -> { lines:[], clients:Set<res>, done:bool }

function jobFor(jobId) {
  let j = jobs.get(jobId);
  if (!j) { j = { lines: [], clients: new Set(), done: false }; jobs.set(jobId, j); }
  return j;
}

function pushLine(jobId, text, stream = "out") {
  const j = jobFor(jobId);
  const evt = { text, stream, t: Date.now() };
  j.lines.push(evt);
  for (const res of j.clients) writeSse(res, "line", evt);
}

function finishJob(jobId, payload) {
  const j = jobFor(jobId);
  j.done = true;
  for (const res of j.clients) { writeSse(res, "done", payload); res.end(); }
  j.clients.clear();
}

function writeSse(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// ── Routes ───────────────────────────────────────────────────────────────────

app.get("/api/tools", (req, res) => {
  const tools = checkTools();
  let devices = [];
  try { devices = listDevices().devices; } catch {}
  res.json({ tools, devices });
});

// Upload one (or several split) APK files → returns jobId + stored file list.
app.post("/api/upload", upload.array("apk", 12), (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: "no file uploaded" });
  const jobId = req.jobId;
  const files = req.files.map(f => ({ name: f.filename, size: f.size, path: f.path }));
  // Primary = base.apk if present, else the largest.
  const primary = files.find(f => f.name.toLowerCase() === "base.apk")
    || files.slice().sort((a, b) => b.size - a.size)[0];
  res.json({ jobId, files, primary: primary.name, dir: path.dirname(files[0].path) });
});

// SSE stream for a job. Replays buffered lines, then streams live ones.
app.get("/api/stream/:jobId", (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.flushHeaders?.();
  const j = jobFor(req.params.jobId);
  for (const evt of j.lines) writeSse(res, "line", evt);
  if (j.done) { writeSse(res, "done", { replayed: true }); return res.end(); }
  j.clients.add(res);
  req.on("close", () => j.clients.delete(res));
});

// FORENSIC — synchronous inspect (fast enough to return inline).
app.post("/api/inspect", (req, res) => {
  const { jobId, file } = req.body || {};
  const apk = resolveApk(jobId, file);
  if (!apk) return res.status(400).json({ error: "APK not found for job" });
  try {
    res.json(inspectApk(apk));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// FORENSIC — Jimple IR + control-flow graph (read-only Soot).
// Resolve to the raw APK Soot can process (bundle → its base APK, extracted once).
function resolveSootApk(jobId, file) {
  const apk = resolveApk(jobId, file);
  if (!apk) return null;
  if (!bundleLib.isBundle(apk)) return apk;
  // Extract the base APK to a stable per-job dir so it's reused across requests.
  const baseDir = path.join(UPLOADS_DIR, jobId, ".soot-base");
  try {
    if (!fs.existsSync(baseDir)) {
      fs.mkdirSync(baseDir, { recursive: true });
      bundleLib.unpack(apk, baseDir);
    }
    const manifest = bundleLib.readManifest(baseDir);
    const base = bundleLib.findBaseApk(baseDir, manifest);
    return base ? path.join(baseDir, base) : null;
  } catch { return null; }
}

app.post("/api/classes", (req, res) => {
  const { jobId, file } = req.body || {};
  const apk = resolveSootApk(jobId, file);
  if (!apk) return res.status(400).json({ error: "APK not found for job" });
  try { res.json({ classes: jimpleLib.listClasses(apk) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/methods", (req, res) => {
  const { jobId, file, className } = req.body || {};
  const apk = resolveSootApk(jobId, file);
  if (!apk) return res.status(400).json({ error: "APK not found for job" });
  if (!className) return res.status(400).json({ error: "className required" });
  try { res.json({ className, methods: jimpleLib.listMethods(apk, className) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/jimple", (req, res) => {
  const { jobId, file, className, subsig } = req.body || {};
  const apk = resolveSootApk(jobId, file);
  if (!apk) return res.status(400).json({ error: "APK not found for job" });
  if (!className) return res.status(400).json({ error: "className required" });
  try { res.json({ className, subsig: subsig || null, jimple: jimpleLib.jimple(apk, className, subsig) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/cfg", (req, res) => {
  const { jobId, file, className, subsig } = req.body || {};
  const apk = resolveSootApk(jobId, file);
  if (!apk) return res.status(400).json({ error: "APK not found for job" });
  if (!className || !subsig) return res.status(400).json({ error: "className and subsig required" });
  try { res.json(jimpleLib.cfg(apk, className, subsig)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Whole-app call graph (methods as nodes, calls as edges). Scoped to a package
// (default: the app's auto-detected base package) and capped for renderability.
app.post("/api/callgraph", (req, res) => {
  const { jobId, file, pkgPrefix, maxNodes } = req.body || {};
  const apk = resolveSootApk(jobId, file);
  if (!apk) return res.status(400).json({ error: "APK not found for job" });
  try { res.json(jimpleLib.callGraph(apk, pkgPrefix, maxNodes)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// HACKING (inject) — async, streams to SSE.
app.post("/api/inject", (req, res) => {
  const { jobId, file, injectAll = true, patterns = [] } = req.body || {};
  const apk = resolveApk(jobId, file);
  if (!apk) return res.status(400).json({ error: "APK not found for job" });

  const outputDir = path.join(OUTPUT_DIR, jobId);
  const log = (line, stream) => pushLine(jobId, line, stream);
  res.json({ jobId, started: true, outputDir });

  inject({ apkPath: apk, outputDir, injectAll, patterns, log })
    .then(r => finishJob(jobId, { kind: "inject", ...r }))
    .catch(e => { log("FATAL: " + e.message, "err"); finishJob(jobId, { kind: "inject", ok: false, error: e.message }); });
});

// HACKING (instrument) — install injected APK on device, capture logcat.
app.post("/api/instrument", (req, res) => {
  const { jobId, device, durationMs = 30000 } = req.body || {};
  const apkDir = path.join(OUTPUT_DIR, jobId);
  if (!fs.existsSync(apkDir)) return res.status(400).json({ error: "no injected output — run inject first" });

  const log = (line, stream) => pushLine(jobId, line, stream);
  res.json({ jobId, started: true });

  instrument({ apkDir, device, durationMs, log })
    .then(r => finishJob(jobId, { kind: "instrument", ...r }))
    .catch(e => { log("FATAL: " + e.message, "err"); finishJob(jobId, { kind: "instrument", ok: false, error: e.message }); });
});

// Download an injected APK.
app.get("/api/download/:jobId/:name", (req, res) => {
  const p = path.join(OUTPUT_DIR, req.params.jobId, sanitize(req.params.name));
  if (!fs.existsSync(p)) return res.status(404).send("not found");
  res.download(p);
});

// Resolve the APK path for a job: explicit file, else base.apk, else largest.
function resolveApk(jobId, file) {
  if (!jobId) return null;
  const dir = path.join(UPLOADS_DIR, jobId);
  if (!fs.existsSync(dir)) return null;
  if (file) {
    const p = path.join(dir, sanitize(file));
    if (fs.existsSync(p)) return p;
  }
  // Accept bundles (.xapk/.apks) too — the inspector unpacks them to the base APK.
  const apks = fs.readdirSync(dir).filter(f => /\.(apk|xapk|apks)$/i.test(f));
  if (!apks.length) return null;
  const base = apks.find(f => f.toLowerCase() === "base.apk");
  if (base) return path.join(dir, base);
  return path.join(dir, apks.sort((a, b) =>
    fs.statSync(path.join(dir, b)).size - fs.statSync(path.join(dir, a)).size)[0]);
}

// multer/file-filter errors → clean JSON.
app.use((err, req, res, next) => {
  if (err) return res.status(400).json({ error: err.message });
  next();
});

app.listen(PORT, () => {
  console.log(`SootSleuth running → http://localhost:${PORT}`);
  const t = checkTools();
  if (!t.java) console.warn("[WARN] java not found — injection will fail. Install a JDK.");
  if (!t.platforms) console.warn("[WARN] Android platforms not found — set ANDROID_HOME.");
  if (!t.adb) console.warn("[WARN] adb not found — instrumentation disabled.");
});
