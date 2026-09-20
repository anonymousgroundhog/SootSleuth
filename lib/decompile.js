/**
 * lib/decompile.js  — JAVA DECOMPILATION (jadx)
 *
 * Decompiles an APK's DEX back to readable Java using jadx, one class at a time
 * (`--single-class`), so the malware-analysis tab can show the actual source of
 * a suspicious class instead of only Soot's Jimple IR.
 *
 * jadx is optional. When it isn't installed the routes report that clearly and
 * the UI degrades — same contract as adb/instrument. Output is cached per job so
 * re-viewing a class (or its neighbours) is instant after the first decompile.
 *
 * Read-only: jadx only reads the APK and writes .java into a temp cache dir.
 */

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const { findJadx } = require("./tools");

const HAVE = () => !!findJadx();

// Where a job's decompiled sources are cached: uploads/<jobId>/.jadx/
function cacheDirFor(apkPath) {
  return path.join(path.dirname(apkPath), ".jadx");
}

// jadx lays a class down at <out>/sources/<pkg>/<Class>.java. Inner classes
// (a.b.C$D) decompile into their outer class's file, so we resolve to the outer.
function sourcePathFor(outDir, className) {
  const outer = className.split("$")[0];
  return path.join(outDir, "sources", ...outer.split(".")) + ".java";
}

// Decompile one class. Returns { className, java, engine, cached } or throws a
// user-facing Error. `--single-class` keeps this fast even on large apps.
function decompileClass(apkPath, className) {
  const jadx = findJadx();
  if (!jadx) {
    const err = new Error("jadx not found — install it to view decompiled Java (see docs/SETUP.md). Jimple IR remains available in Forensic mode.");
    err.code = "NO_JADX";
    throw err;
  }
  if (!className) throw new Error("className required");

  const outDir = cacheDirFor(apkPath);
  const target = sourcePathFor(outDir, className);
  if (fs.existsSync(target)) {
    return { className, java: fs.readFileSync(target, "utf8"), engine: "jadx", cached: true };
  }

  fs.mkdirSync(outDir, { recursive: true });
  // --single-class decompiles just this class (and its inners); the other flags
  // keep it fast and resilient on obfuscated/broken dex.
  const args = [
    "--single-class", className,
    "-d", outDir,
    "--no-res",              // skip resources — we only want code here
    "--no-imports",          // fully-qualified names read clearer for analysis
    "--show-bad-code",       // emit best-effort output rather than failing
    "--threads-count", "1",
    apkPath,
  ];
  const r = spawnSync(jadx, args, {
    encoding: "utf8", timeout: 120000, maxBuffer: 64 * 1024 * 1024,
  });

  if (fs.existsSync(target)) {
    return { className, java: fs.readFileSync(target, "utf8"), engine: "jadx", cached: false };
  }
  // jadx exited without producing the file — surface why.
  const why = (r.stderr || r.stdout || "").split("\n").filter(Boolean).slice(-4).join(" ").slice(-400);
  if (r.error && r.error.code === "ETIMEDOUT") throw new Error(`jadx timed out decompiling ${className}`);
  throw new Error(`jadx produced no source for ${className}${why ? " — " + why : ""}`);
}

module.exports = { decompileClass, jadxAvailable: HAVE };
