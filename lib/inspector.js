/**
 * lib/inspector.js  — FORENSIC MODE
 *
 * Static analysis of an APK for ad-SDK traces, Play Store references, and
 * basic manifest metadata. Adapted from MADPro apk_inspector.js.
 *
 * Cross-platform: prefers the `strings` binary when present (fast), otherwise
 * falls back to a pure-JS printable-string scan of the extracted bytes so the
 * tool still works on Windows without unix tooling.
 */

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { findBin, findBuildTool } = require("./tools");

// ── SDK signatures ───────────────────────────────────────────────────────────
const DEX_AD_PATTERNS = [
  { pattern: /Lcom\/google\/android\/gms\/ads/, name: "Google AdMob" },
  { pattern: /Lcom\/google\/ads/,               name: "Google Ads" },
  { pattern: /Lcom\/facebook\/ads/,             name: "Facebook Audience Network" },
  { pattern: /Lcom\/applovin/,                  name: "AppLovin" },
  { pattern: /Lcom\/unity3d\/ads/,              name: "Unity Ads" },
  { pattern: /Lcom\/ironsource/,                name: "IronSource" },
  { pattern: /Lcom\/vungle/,                    name: "Vungle" },
  { pattern: /Lcom\/mopub/,                     name: "MoPub" },
  { pattern: /Lcom\/inmobi/,                    name: "InMobi" },
  { pattern: /Lcom\/chartboost/,                name: "Chartboost" },
  { pattern: /Lcom\/startapp/,                  name: "StartApp" },
  { pattern: /Lcom\/tapjoy/,                    name: "Tapjoy" },
  { pattern: /Lcom\/mintegral/,                 name: "Mintegral" },
  { pattern: /Lcom\/fyber/,                     name: "Fyber" },
  { pattern: /Lcom\/digitalturbine/,            name: "Digital Turbine" },
  { pattern: /Lcom\/adcolony/,                  name: "AdColony" },
];

const METAINF_AD_PATTERNS = [
  { pattern: /applovin\/mediation/i,             name: "AppLovin Mediation" },
  { pattern: /facebook-adapter/i,                name: "Facebook Audience Network" },
  { pattern: /google-adapter|google-ad-manager/i, name: "Google AdMob" },
  { pattern: /ironsource/i,                       name: "IronSource" },
  { pattern: /vungle/i,                           name: "Vungle" },
  { pattern: /unityads/i,                         name: "Unity Ads" },
  { pattern: /inmobi/i,                           name: "InMobi" },
  { pattern: /mintegral/i,                        name: "Mintegral" },
  { pattern: /chartboost/i,                       name: "Chartboost" },
  { pattern: /audience_network/i,                 name: "Facebook Audience Network" },
  { pattern: /privacysandbox\.ads/i,              name: "Google Privacy Sandbox Ads" },
];

const ASSET_AD_PATTERNS = [
  { pattern: /audience_network\.dex/i, name: "Facebook Audience Network" },
  { pattern: /applovin/i,              name: "AppLovin" },
  { pattern: /unity-ads/i,             name: "Unity Ads" },
];

const DEX_PLAY_PATTERNS = [
  { pattern: /Lcom\/android\/vending/,                  name: "Google Play Billing" },
  { pattern: /com\.android\.vending\.INSTALL_REFERRER/, name: "Play Install Referrer" },
  { pattern: /Lcom\/google\/android\/play/,             name: "Google Play API" },
];

// ── ZIP / string helpers ─────────────────────────────────────────────────────

const HAVE_UNZIP   = !!findBin("unzip");
const HAVE_STRINGS = !!findBin("strings");

function listZipEntries(apkPath) {
  if (HAVE_UNZIP) {
    const r = spawnSync("unzip", ["-l", apkPath], { encoding: "utf8", timeout: 15000 });
    if (r.stdout) {
      return r.stdout.split("\n")
        .map(l => l.trim().replace(/^[\d\s\-:]+/, "").trim())
        .filter(Boolean);
    }
  }
  return listZipEntriesJS(apkPath);
}

function extractEntry(apkPath, entryName) {
  if (HAVE_UNZIP) {
    const r = spawnSync("unzip", ["-p", apkPath, entryName], {
      encoding: "buffer", timeout: 30000, maxBuffer: 256 * 1024 * 1024,
    });
    if (r.status === 0) return r.stdout;
  }
  return extractEntryJS(apkPath, entryName);
}

// Pure-JS ZIP reader (central directory), used when `unzip` is unavailable.
// Handles STORE (0) and DEFLATE (8) — the only methods APKs use.
function readCentralDir(apkPath) {
  const buf = fs.readFileSync(apkPath);
  // Find End Of Central Directory record (0x06054b50), scanning from the tail.
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i > buf.length - 22 - 65536; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("Not a ZIP/APK (no EOCD)");
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let n = 0; n < count && off + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method   = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const uncompSize = buf.readUInt32LE(off + 24);
    const nameLen  = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const cmtLen   = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.toString("utf8", off + 46, off + 46 + nameLen);
    entries.push({ name, method, compSize, uncompSize, localOff });
    off += 46 + nameLen + extraLen + cmtLen;
  }
  return { buf, entries };
}

function listZipEntriesJS(apkPath) {
  try { return readCentralDir(apkPath).entries.map(e => e.name); }
  catch { return []; }
}

// Detailed entry list: { name, size, compSize, method }. Always uses the pure-JS
// central-directory reader (not `unzip -l`) so names are clean and uncompressed
// sizes are available — the file browser needs both.
function listZipEntriesDetailed(apkPath) {
  try {
    return readCentralDir(apkPath).entries.map(e => ({
      name: e.name, size: e.uncompSize, compSize: e.compSize, method: e.method,
    }));
  } catch { return []; }
}

function extractEntryJS(apkPath, entryName) {
  try {
    const { buf, entries } = readCentralDir(apkPath);
    const e = entries.find(x => x.name === entryName);
    if (!e) return null;
    // Local file header: name+extra lengths at offsets 26/28 from localOff.
    const lh = e.localOff;
    if (buf.readUInt32LE(lh) !== 0x04034b50) return null;
    const nameLen  = buf.readUInt16LE(lh + 26);
    const extraLen = buf.readUInt16LE(lh + 28);
    const dataStart = lh + 30 + nameLen + extraLen;
    const comp = buf.subarray(dataStart, dataStart + e.compSize);
    if (e.method === 0) return Buffer.from(comp);
    if (e.method === 8) return require("zlib").inflateRawSync(comp);
    return null;
  } catch { return null; }
}

function stringsOf(bufOrEntry) {
  if (!bufOrEntry || bufOrEntry.length === 0) return "";
  if (HAVE_STRINGS) {
    const r = spawnSync("strings", [], {
      input: bufOrEntry, encoding: "utf8", timeout: 30000, maxBuffer: 64 * 1024 * 1024,
    });
    if (r.stdout) return r.stdout;
  }
  return stringsJS(bufOrEntry);
}

// Minimal `strings`: runs of >=4 printable ASCII chars.
function stringsJS(buf) {
  let out = [];
  let cur = "";
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) {
      cur += String.fromCharCode(c);
    } else {
      if (cur.length >= 4) out.push(cur);
      cur = "";
    }
  }
  if (cur.length >= 4) out.push(cur);
  return out.join("\n");
}

// aapt2 badging → package metadata (optional; null if aapt2 missing).
function badging(apkPath) {
  const aapt = findBuildTool("aapt2") || findBin("aapt");
  if (!aapt) return null;
  try {
    const r = spawnSync(aapt, ["dump", "badging", apkPath], { encoding: "utf8", timeout: 15000 });
    const out = r.stdout || "";
    if (!out) return null;
    return {
      package:     out.match(/^package: name='([^']+)'/m)?.[1] ?? null,
      versionName: out.match(/versionName='([^']+)'/)?.[1] ?? null,
      versionCode: out.match(/versionCode='([^']+)'/)?.[1] ?? null,
      appName:     out.match(/^application-label(?:-en)?:'([^']+)'/m)?.[1] ?? null,
      sdkVersion:  out.match(/sdkVersion:'([^']+)'/)?.[1] ?? null,
      targetSdk:   out.match(/targetSdkVersion:'([^']+)'/)?.[1] ?? null,
    };
  } catch { return null; }
}

// aapt2 dump permissions → accurate permission list. The `strings` scan of a
// binary AndroidManifest.xml (AXML) returns nothing, so aapt2 is the only
// reliable source when present.
function aaptPermissions(apkPath) {
  const aapt = findBuildTool("aapt2") || findBin("aapt");
  if (!aapt) return null;
  try {
    const r = spawnSync(aapt, ["dump", "permissions", apkPath], { encoding: "utf8", timeout: 15000 });
    const out = r.stdout || "";
    if (!out) return null;
    const perms = [...out.matchAll(/uses-permission: name='([^']+)'/g)].map(m => m[1]);
    return perms.length ? perms : null;
  } catch { return null; }
}

// A bundle (.xapk / .apks) is a ZIP of .apk files. Detect it and return the
// inner base APK path (extracted to a temp dir) plus any manifest.json metadata.
// Returns null when apkPath is a plain APK.
function resolveBundle(apkPath) {
  const ext = path.extname(apkPath).toLowerCase();
  const entries = listZipEntries(apkPath);
  const innerApks = entries.filter(e => /\.apk$/i.test(e) && !e.includes("/"));
  const looksBundle = ext === ".xapk" || ext === ".apks" || innerApks.length > 0;
  if (!looksBundle || !innerApks.length) return null;

  // manifest.json (APKPure XAPK) carries package/version/permissions directly.
  let xapkManifest = null;
  const mjBuf = extractEntry(apkPath, "manifest.json");
  if (mjBuf) { try { xapkManifest = JSON.parse(mjBuf.toString("utf8")); } catch {} }

  // Pick the base APK: manifest.json's base entry, else "base.apk", else the
  // package-named apk, else the largest inner apk.
  let baseName = null;
  if (xapkManifest?.split_apks) {
    baseName = (xapkManifest.split_apks.find(s => s.id === "base") || {}).file || null;
  }
  if (!baseName || !innerApks.includes(baseName)) {
    baseName = innerApks.find(n => n.toLowerCase() === "base.apk")
      || (xapkManifest?.package_name && innerApks.find(n => n.startsWith(xapkManifest.package_name)))
      || innerApks.find(n => !/^(config\.|split_config\.)/i.test(n))
      || innerApks[0];
  }

  const buf = extractEntry(apkPath, baseName);
  if (!buf) return { xapkManifest, innerApks, baseName, basePath: null };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sootsleuth-xapk-"));
  const basePath = path.join(tmpDir, path.basename(baseName));
  fs.writeFileSync(basePath, buf);
  return { xapkManifest, innerApks, baseName, basePath, tmpDir };
}

// ── Main forensic inspection ─────────────────────────────────────────────────

function inspectApk(outerPath) {
  // Bundles (.xapk/.apks) hold the real APK inside — inspect that, but keep the
  // outer file's name/size for display and use manifest.json as a metadata source.
  const bundle = resolveBundle(outerPath);
  const apkPath = bundle && bundle.basePath ? bundle.basePath : outerPath;
  try {
    return inspectSingleApk(apkPath, outerPath, bundle);
  } finally {
    if (bundle?.tmpDir) { try { fs.rmSync(bundle.tmpDir, { recursive: true, force: true }); } catch {} }
  }
}

function inspectSingleApk(apkPath, outerPath, bundle) {
  const adSdks = new Set();
  const playTraces = new Set();
  const permissions = new Set();

  const entries = listZipEntries(apkPath);

  // Layer 1: ZIP listing
  for (const entry of entries) {
    for (const { pattern, name } of METAINF_AD_PATTERNS)
      if (entry.startsWith("META-INF/") && pattern.test(entry)) adSdks.add(name);
    for (const { pattern, name } of ASSET_AD_PATTERNS)
      if (entry.startsWith("assets/") && pattern.test(entry)) adSdks.add(name);
  }

  // Layer 2: DEX string scan
  const dexFiles = entries.filter(e => /^classes\d*\.dex$/.test(e));
  for (const dexFile of dexFiles) {
    const buf = extractEntry(apkPath, dexFile);
    if (!buf) continue;
    const text = stringsOf(buf);
    for (const { pattern, name } of DEX_AD_PATTERNS)   if (pattern.test(text)) adSdks.add(name);
    for (const { pattern, name } of DEX_PLAY_PATTERNS) if (pattern.test(text)) playTraces.add(name);
  }

  // Layer 3: permissions + manifest-derived Play traces.
  // Preferred source is `aapt2 dump permissions` (accurate); a binary AXML
  // yields nothing under `strings`, so we fall back to the XAPK manifest.json
  // permission list, then to a best-effort strings scan.
  let permSource = "none";
  const aaptPerms = aaptPermissions(apkPath);
  if (aaptPerms) {
    aaptPerms.forEach(p => permissions.add(p));
    permSource = "aapt2";
  } else if (bundle?.xapkManifest?.permissions?.length) {
    bundle.xapkManifest.permissions.forEach(p => permissions.add(p));
    permSource = "xapk-manifest";
  }

  const manifestBuf = extractEntry(apkPath, "AndroidManifest.xml");
  if (manifestBuf) {
    const m = stringsOf(manifestBuf);
    if (permSource === "none") {
      for (const perm of m.match(/android\.permission\.[A-Z_]+/g) || []) permissions.add(perm);
      if (permissions.size) permSource = "strings";
    }
    if (/com\.android\.vending|BILLING|InAppBillingService/i.test(m)) playTraces.add("Google Play Billing (Manifest)");
    if (/com\.google\.android\.c2dm|FCM|GCM/i.test(m)) playTraces.add("Google Play Services (FCM/GCM)");
  }
  // Billing shows up in the XAPK permission list too.
  if ([...permissions].some(p => /vending\.BILLING/i.test(p))) playTraces.add("Google Play Billing (Manifest)");

  // Prefer aapt2 badging; fall back to XAPK manifest.json metadata.
  let meta = badging(apkPath);
  const mj = bundle?.xapkManifest;
  if (mj) {
    meta = {
      package:     meta?.package     ?? mj.package_name ?? null,
      versionName: meta?.versionName ?? mj.version_name ?? null,
      versionCode: meta?.versionCode ?? mj.version_code ?? null,
      appName:     meta?.appName     ?? mj.name ?? null,
      sdkVersion:  meta?.sdkVersion  ?? mj.min_sdk_version ?? null,
      targetSdk:   meta?.targetSdk   ?? mj.target_sdk_version ?? null,
    };
  }

  const isBundle = !!(bundle && bundle.innerApks);
  return {
    file: path.basename(outerPath),
    sizeBytes: fs.statSync(outerPath).size,
    bundle: isBundle ? {
      type: path.extname(outerPath).toLowerCase().replace(".", "") || "bundle",
      baseApk: bundle.baseName,
      splitCount: bundle.innerApks.length - 1,
    } : null,
    meta,
    dexCount: dexFiles.length,
    entryCount: entries.length,
    hasAds: adSdks.size > 0,
    adSdks: [...adSdks].sort(),
    hasPlayStoreTraces: playTraces.size > 0,
    playStoreTraces: [...playTraces].sort(),
    permissions: [...permissions].sort(),
    permSource,
    method: (HAVE_UNZIP ? "unzip+strings" : "pure-js") + (isBundle ? " (bundle→base apk)" : ""),
  };
}

// Shared ZIP/strings/metadata helpers, reused by the malware-analysis module so
// both modes read the APK the same way (unzip+strings, pure-JS fallback).
module.exports = {
  inspectApk,
  listZipEntries, listZipEntriesDetailed, extractEntry, stringsOf,
  resolveBundle, aaptPermissions, badging,
};
