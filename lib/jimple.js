/**
 * lib/jimple.js  — FORENSIC MODE (Jimple IR + control-flow graph)
 *
 * Wraps java/JimpleDumper.java: lists the app's classes, a class's methods, its
 * Jimple source, and a method's control-flow graph (as node/edge JSON). Read-only
 * — Soot loads the APK but never writes it back.
 *
 * Each mode is one short-lived JVM run. Soot start-up dominates, so results are
 * memoised per (apk, mode, args) for the life of the process.
 */

const path = require("path");
const fs = require("fs");
const { spawnSync } = require("child_process");
const {
  CP_SEP, findBin, findAndroidPlatforms, jarClasspath, JAVA_SRC_DIR,
} = require("./tools");

const DUMPER_SRC   = path.join(JAVA_SRC_DIR, "JimpleDumper.java");
const DUMPER_CLASS = path.join(JAVA_SRC_DIR, "JimpleDumper.class");

const cache = new Map(); // key -> parsed result

function ensureCompiled() {
  const upToDate = fs.existsSync(DUMPER_CLASS) &&
    fs.statSync(DUMPER_SRC).mtimeMs <= fs.statSync(DUMPER_CLASS).mtimeMs;
  if (upToDate) return true;
  if (!fs.existsSync(DUMPER_SRC)) throw new Error("JimpleDumper.java not found");
  const javac = findBin("javac") || "javac";
  const r = spawnSync(javac, ["-cp", jarClasspath(), "-d", JAVA_SRC_DIR, DUMPER_SRC],
    { encoding: "utf8" });
  if (r.status !== 0) throw new Error("javac failed: " + (r.stderr || r.stdout || "").slice(0, 500));
  return true;
}

// Run JimpleDumper <mode> <platforms> <apk> [extra…] and return stdout.
// Soot's own stderr noise is discarded; only a non-zero exit surfaces an error.
function runDumper(apkPath, mode, extra = []) {
  ensureCompiled();
  const platforms = findAndroidPlatforms();
  if (!platforms) throw new Error("Android platforms not found (set ANDROID_HOME)");

  const cp = [JAVA_SRC_DIR, jarClasspath()].join(CP_SEP);
  const java = findBin("java") || "java";
  const args = ["-Xmx4g", "-Xms256m", "-cp", cp, "JimpleDumper", mode, platforms, apkPath, ...extra];

  const r = spawnSync(java, args, {
    encoding: "utf8",
    timeout: 5 * 60 * 1000,
    maxBuffer: 128 * 1024 * 1024,
  });
  if (r.error) throw new Error("java run failed: " + r.error.message);
  if (r.status !== 0) {
    // JimpleDumper prints "ERROR: …" to stderr for user errors (class not found).
    const msg = (r.stderr || "").split("\n").find(l => l.startsWith("ERROR:"))
      || (r.stderr || "").trim().slice(-400) || "JimpleDumper exited " + r.status;
    throw new Error(msg.replace(/^ERROR:\s*/, ""));
  }
  return r.stdout || "";
}

function memo(key, fn) {
  if (cache.has(key)) return cache.get(key);
  const v = fn();
  cache.set(key, v);
  return v;
}

// List the app's own class names (sorted).
function listClasses(apkPath) {
  return memo(`classes\0${apkPath}`, () =>
    runDumper(apkPath, "--classes").split("\n").map(s => s.trim()).filter(Boolean));
}

// List a class's methods → [{ subsig, name }].
function listMethods(apkPath, className) {
  return memo(`methods\0${apkPath}\0${className}`, () =>
    runDumper(apkPath, "--methods", [className]).split("\n")
      .map(l => l.trim()).filter(Boolean)
      .map(l => { const [subsig, name] = l.split("\t"); return { subsig, name }; }));
}

// Jimple source text for a class (whole class if subsig omitted, else one method).
function jimple(apkPath, className, subsig) {
  const key = `jimple\0${apkPath}\0${className}\0${subsig || ""}`;
  return memo(key, () =>
    runDumper(apkPath, "--jimple", subsig ? [className, subsig] : [className]));
}

// Control-flow graph JSON for one method: { method, nodes:[{id,text,kind}], edges:[{from,to,kind}] }.
function cfg(apkPath, className, subsig) {
  if (!subsig) throw new Error("method subsignature required for CFG");
  const key = `cfg\0${apkPath}\0${className}\0${subsig}`;
  return memo(key, () => {
    const out = runDumper(apkPath, "--cfg", [className, subsig]).trim();
    try { return JSON.parse(out); }
    catch (e) { throw new Error("could not parse CFG JSON: " + out.slice(0, 300)); }
  });
}

// Whole-app call graph JSON, scoped to a package (default: app's base package)
// and capped at maxNodes. pkgPrefix may be a manifest-package hint from the caller.
function callGraph(apkPath, pkgPrefix, maxNodes) {
  const prefix = (pkgPrefix || "").trim();
  const cap = Number.isFinite(+maxNodes) && +maxNodes > 0 ? String(Math.floor(+maxNodes)) : "400";
  const key = `callgraph\0${apkPath}\0${prefix}\0${cap}`;
  return memo(key, () => {
    const extra = prefix ? [prefix, cap] : ["", cap];
    const out = runDumper(apkPath, "--callgraph", extra).trim();
    try { return JSON.parse(out); }
    catch (e) { throw new Error("could not parse call-graph JSON: " + out.slice(0, 300)); }
  });
}

module.exports = { listClasses, listMethods, jimple, cfg, callGraph };
