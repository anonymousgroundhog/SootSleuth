/**
 * lib/instrument.js  — HACKING MODE (run on device)
 *
 * Install the injected APK on a connected device/emulator, launch it, capture
 * logcat (filtered to the SootInjection tag), then uninstall. Streams all
 * output through the `log` callback for the web UI.
 *
 * Adapted from MADPro command-line-tool/commands/instrument.js.
 */

const path = require("path");
const fs = require("fs");
const os = require("os");
const { spawn, spawnSync } = require("child_process");
const { run } = require("./runner");
const { findAdb, findBuildTool, findBin } = require("./tools");
const bundle = require("./bundle");

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function listDevices() {
  const adb = findAdb();
  if (!adb) return { adb: null, devices: [] };
  const r = spawnSync(adb, ["devices"], { encoding: "utf8", timeout: 10000 });
  const devices = (r.stdout || "").split("\n").slice(1)
    .map(l => l.trim()).filter(Boolean)
    .map(l => { const [serial, state] = l.split(/\s+/); return { serial, state }; })
    .filter(d => d.serial && d.state === "device");
  return { adb, devices };
}

function pkgOf(apkPath) {
  for (const tool of [findBuildTool("aapt2"), findBin("aapt"), "aapt2", "aapt"]) {
    if (!tool) continue;
    try {
      const r = spawnSync(tool, ["dump", "badging", apkPath], { encoding: "utf8", timeout: 15000 });
      const m = (r.stdout || "").match(/^package: name='([^']+)'/m);
      if (m) return m[1];
    } catch {}
  }
  return null;
}

function streamLogcat(adb, serialArgs, pkg, durationMs, log) {
  return new Promise(resolve => {
    const pidRes = spawnSync(adb, [...serialArgs, "shell", "pidof", pkg], { encoding: "utf8" });
    const pid = (pidRes.stdout || "").trim();
    const args = pid
      ? [...serialArgs, "logcat", "--pid", pid, "-v", "time"]
      : [...serialArgs, "logcat", "-v", "time", "-s", "SootInjection:D"];

    log(`[INFO] Capturing logcat for ${durationMs / 1000}s…`, "sys");
    const proc = spawn(adb, args);
    const timeout = setTimeout(() => { try { proc.kill(); } catch {} }, durationMs);
    const onLine = l => { if (l.trim()) log(l.trim(), "out"); };
    proc.stdout.on("data", d => d.toString().split("\n").forEach(onLine));
    proc.stderr.on("data", d => d.toString().split("\n").forEach(onLine));
    proc.on("close", () => { clearTimeout(timeout); resolve(); });
    proc.on("error", err => { clearTimeout(timeout); log("ERROR: " + err.message, "err"); resolve(); });
  });
}

/**
 * instrument({ apkDir, device, durationMs, log }) -> { ok, pkg }
 * apkDir — directory holding the injected output: loose APK(s) (base + splits)
 *          for a plain-APK job, or a single injected .xapk/.apks bundle.
 */
async function instrument({ apkDir, device, durationMs = 30000, log }) {
  const emit = (l, s = "sys") => log && log(l, s);
  const { adb, devices } = listDevices();
  if (!adb) { emit("ERROR: adb not found. Install Android platform-tools.", "err"); return { ok: false }; }

  const serial = device || (devices[0] && devices[0].serial);
  if (!serial) { emit("ERROR: no connected device/emulator (adb devices is empty).", "err"); return { ok: false }; }
  const serialArgs = ["-s", serial];
  emit(`[INFO] Using device: ${serial}`);

  // Resolve the APK set. Prefer loose .apk files; if the output is an injected
  // bundle (.xapk/.apks), unpack it to a temp dir and install its split set.
  let apks = fs.readdirSync(apkDir)
    .filter(f => f.toLowerCase().endsWith(".apk"))
    .map(f => path.join(apkDir, f)).sort();
  let tmpDir = null;

  if (!apks.length) {
    const bundleFile = fs.readdirSync(apkDir).find(f => bundle.isBundle(f));
    if (bundleFile) {
      emit(`[INFO] Output is a bundle (${bundleFile}) — unpacking for install-multiple…`);
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sootsleuth-run-"));
      bundle.unpack(path.join(apkDir, bundleFile), tmpDir);
      apks = fs.readdirSync(tmpDir)
        .filter(f => f.toLowerCase().endsWith(".apk"))
        .map(f => path.join(tmpDir, f)).sort();
    }
  }

  try {
    return await runInstall({ apks, adb, serialArgs, serial, durationMs, log, emit });
  } finally {
    if (tmpDir) { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {} }
  }
}

// Core install → launch → logcat → uninstall, given a resolved APK set.
async function runInstall({ apks, adb, serialArgs, durationMs, log, emit }) {
  if (!apks.length) { emit("ERROR: no APKs to install.", "err"); return { ok: false }; }

  // Base = base.apk, else the first non-split APK (bundle base is package-named,
  // not "base.apk"), else the largest.
  const baseApk =
    apks.find(p => path.basename(p).toLowerCase() === "base.apk") ||
    apks.find(p => !/^(config\.|split_config\.|split_)/i.test(path.basename(p))) ||
    apks.slice().sort((a, b) => fs.statSync(b).size - fs.statSync(a).size)[0];
  const pkg = pkgOf(baseApk);
  if (!pkg) { emit("ERROR: could not resolve package name (aapt2 needed).", "err"); return { ok: false }; }
  emit(`[INFO] Package: ${pkg}`);

  // Remove any existing install to avoid signature mismatch.
  const probe = spawnSync(adb, [...serialArgs, "shell", "pm", "path", "--user", "0", pkg], { encoding: "utf8", timeout: 10000 });
  if ((probe.stdout || "").includes("package:")) {
    emit(`[INFO] Uninstalling existing ${pkg}…`);
    const u = spawnSync(adb, [...serialArgs, "uninstall", pkg], { encoding: "utf8", timeout: 30000 });
    if (!/^Success/i.test((u.stdout || "").trim()))
      spawnSync(adb, [...serialArgs, "shell", "pm", "uninstall", "--user", "0", pkg], { encoding: "utf8", timeout: 30000 });
  }

  spawnSync(adb, [...serialArgs, "logcat", "-c"], { timeout: 5000 });

  emit(`[INFO] Installing (${apks.length} APK${apks.length > 1 ? "s" : ""})…`);
  const installed = apks.length > 1
    ? await run(adb, [...serialArgs, "install-multiple", "-r", "-t", "-g", ...apks], { onLine: log })
    : await run(adb, [...serialArgs, "install", "-r", "-t", "-g", baseApk], { onLine: log });
  if (!installed) { emit("[FAILED] install failed.", "err"); return { ok: false, pkg }; }
  emit("[OK] Installed (runtime permissions granted).");

  emit(`[INFO] Launching ${pkg}…`);
  await run(adb, [...serialArgs, "shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"], { onLine: log });
  await sleep(1500);

  await streamLogcat(adb, serialArgs, pkg, durationMs, log);

  emit(`[INFO] Uninstalling ${pkg}…`);
  await run(adb, [...serialArgs, "shell", "pm", "uninstall", pkg], { onLine: log });
  emit("[DONE] Instrumentation complete.");
  return { ok: true, pkg };
}

module.exports = { instrument, listDevices };
