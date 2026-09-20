/**
 * lib/droidlysis.js — SUSPICIOUS APP CODE (DroidLysis)
 *
 * Runs DroidLysis (https://github.com/cryptax/droidlysis) over the uploaded APK
 * and turns its machine-readable report into the shape the "Suspicious app code"
 * tab renders.
 *
 * DroidLysis is a property extractor: it unpacks the APK (apktool / baksmali /
 * dex2jar), then pattern-matches disassembled Smali, the raw file contents
 * ("wide"), and native ARM code against its conf/*.conf rule sets. Each rule is
 * a section that either fires or doesn't, so a report is mostly a big set of
 * booleans — which on its own reads as noise. We keep only the properties that
 * fired and re-attach each rule's `description=` from the conf files, so the UI
 * can say *why* a hit matters instead of printing a bare rule name.
 *
 * DroidLysis is optional, exactly like jadx: when it isn't installed the route
 * reports that clearly (code NO_DROIDLYSIS) and the UI degrades to a notice.
 *
 * Runs slow (full unpack + disassembly of every DEX), so the route is async and
 * streams progress over SSE rather than blocking a request. Results are cached
 * per job so re-opening the tab is instant.
 *
 * Read-only: DroidLysis only reads the APK and writes its analysis into a temp
 * dir under the job's upload folder. Nothing is executed.
 */

const path = require("path");
const fs = require("fs");
const { run } = require("./runner");
const { findDroidlysis, findDroidlysisConfig, droidlysisBackends } = require("./tools");

// Bump when the shaped-report schema changes, so caches written by an older
// build are re-run instead of served with missing or stale fields.
const REPORT_VERSION = 1;

// Where a job's DroidLysis output lives: uploads/<jobId>/.droidlysis/
function outDirFor(apkPath) {
  return path.join(path.dirname(apkPath), ".droidlysis");
}
function cachePathFor(apkPath) {
  return path.join(outDirFor(apkPath), "sootsleuth-report.json");
}

// ── conf parsing ─────────────────────────────────────────────────────────────
// DroidLysis' rule files are INI-ish: a [section] per property, with `pattern=`
// and `description=` keys. The JSON report gives us only the section names that
// fired, so we read the descriptions back out to explain each hit.
// Cached per process — the conf files don't change while the server runs.
let descCache = null;

function parseConf(file) {
  const out = {};
  let section = null;
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch { return out; }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = line.match(/^\[(.+)\]$/);
    if (sec) { section = sec[1]; out[section] = out[section] || {}; continue; }
    if (!section) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim();
    if (key === "description" || key === "pattern") out[section][key] = val;
  }
  return out;
}

// Rule descriptions keyed by group → section → { description, pattern }.
function ruleDescriptions() {
  if (descCache) return descCache;
  const confDir = findDroidlysisConfig();
  descCache = { smali: {}, wide: {}, arm: {}, kit: {} };
  if (confDir) {
    descCache.smali = parseConf(path.join(confDir, "smali.conf"));
    descCache.wide = parseConf(path.join(confDir, "wide.conf"));
    descCache.arm = parseConf(path.join(confDir, "arm.conf"));
    descCache.kit = parseConf(path.join(confDir, "kit.conf"));
  }
  return descCache;
}

// ── report shaping ───────────────────────────────────────────────────────────

// Properties whose value is a list/scalar rather than a fired/not-fired flag.
// They're surfaced separately instead of being treated as rule hits.
const WIDE_VALUE_KEYS = new Set(["app_name", "phonenumbers", "urls", "base64_strings"]);
const SMALI_VALUE_KEYS = new Set(["multidex"]);

// A rule "fired" when its value is true, or a non-empty list.
function fired(v) {
  if (v === true) return true;
  if (Array.isArray(v)) return v.length > 0;
  return false;
}

// Turn one property group (smali/wide/arm) into sorted, described hits.
function hitsFor(group, props, confGroup) {
  const descs = ruleDescriptions()[confGroup] || {};
  const skip = group === "wide" ? WIDE_VALUE_KEYS : group === "smali" ? SMALI_VALUE_KEYS : new Set();
  const hits = [];
  for (const [name, value] of Object.entries(props || {})) {
    if (skip.has(name)) continue;
    if (!fired(value)) continue;
    const d = descs[name] || {};
    hits.push({
      group,
      name,
      why: d.description || "",
      pattern: d.pattern || "",
      // `multidex`-style list properties carry their matches; flags don't.
      values: Array.isArray(value) ? value : null,
    });
  }
  return hits.sort((a, b) => a.name.localeCompare(b.name));
}

// Third-party SDKs/trackers DroidLysis recognises (ad, analytics, dev kits).
// By default DroidLysis rules these namespaces *out* of its code searches, so
// this list is context: what else is bundled in the app.
function kitsFor(kits) {
  const descs = ruleDescriptions().kit || {};
  return Object.entries(kits || {})
    .filter(([, v]) => fired(v))
    .map(([name]) => ({ name, why: (descs[name] || {}).description || "" }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

// Heuristic grouping so the UI can lead with what matters. DroidLysis doesn't
// score or rank — every rule is equal to it — so this ordering is ours, not a
// verdict from the tool. Names are matched loosely because the rule set grows.
// Order matters: the first pattern that matches wins, so the more specific and
// more security-relevant categories are listed before the broad ones.
const CATEGORY_RULES = [
  // Root/su indicators live in "Privilege & persistence" instead — they're an
  // access-escalation signal first, even though they're also used for evasion.
  ["Evasion & anti-analysis", /emulator|qemu|genymotion|andy|bluestacks|nox|xposed|frida|debug|anti[_-]|sandbox|virtualbox|goldfish|build_prop|tracer|ptrace|nop|stacktrace|hide_/],
  ["Dynamic code & packing", /dexclassloader|class_?loader|packed|dynamic|native_load|loaddex|load_library|jni|reflection|invoke|base64|decrypt|encrypt|cipher|crypto|obfusc|apkprotect|bangcle|ijiami|qihoo|tencent|packer|zip|encryption/],
  ["Privilege & persistence", /admin|device_admin|boot|persist|accessibility_service|overlay|alert_window|install|uninstall|package_manager|root|\bsu\b|su_|_su\b|superuser|busybox|shell|exec|runtime_exec|check_permission|package_sig|get_package_info/],
  ["Device & user surveillance", /sms|mms|call|contact|camera|record|audio|mic|location|gps|screenshot|screen|keylog|accessibility|clipboard|browser_history|calendar|photo|cookie|email|vibrate/],
  ["Network & exfiltration", /url|uri|http|socket|smtp|ftp|dns|upload|download|post|server|c2|tor|proxy|telnet|irc|webview|javascript|user_agent|ip_address|json/],
  ["Device identity & fingerprint", /imei|imsi|android_id|serial|mac|subscriber|sim|operator|device_id|build_serial|advertising|fingerprint|uuid|model|brand|manufacturer|board|product|hardware|cpu_abi|version|battery/],
];

function categorize(name) {
  for (const [label, re] of CATEGORY_RULES) if (re.test(name)) return label;
  return "Other behaviors";
}

// Build the response payload from DroidLysis' report.json.
// `backends` says which unpacking tools were actually available: without them
// whole layers of the analysis never ran, and we must not present the result as
// if they had.
function shapeReport(raw, meta, backends = { missing: [] }) {
  const smali = hitsFor("smali", raw.smali_properties, "smali");
  const wide = hitsFor("wide", raw.wide_properties, "wide");
  const arm = hitsFor("arm", raw.arm_properties, "arm");
  const allHits = [...smali, ...wide, ...arm];

  // Group hits into categories for display, largest group first.
  const byCat = new Map();
  for (const h of allHits) {
    const c = categorize(h.name);
    if (!byCat.has(c)) byCat.set(c, []);
    byCat.get(c).push(h);
  }
  const categories = [...byCat.entries()]
    .map(([name, hits]) => ({ name, hits }))
    .sort((a, b) => b.hits.length - a.hits.length || a.name.localeCompare(b.name));

  const manifest = raw.manifest_properties || {};
  const wideProps = raw.wide_properties || {};
  const smaliProps = raw.smali_properties || {};

  // Missing unpack tools silently remove whole analysis layers, and a "0 hits"
  // result then reads as "clean" when it really means "not inspected".
  // Severity differs, though: without apktool/baksmali the code is never
  // disassembled and the findings are not usable as a negative result, whereas
  // a missing dex2jar only costs the DEX→JAR convenience step. Flag the first
  // case loudly and the second as a footnote, so the warning stays meaningful.
  const missing = backends.missing || [];
  const noDisasm = missing.includes("baksmali") || missing.includes("apktool");
  const skipped = [];
  if (noDisasm) {
    skipped.push("Smali code analysis (no disassembly)",
                 "manifest parsing (package, permissions, components)");
  }
  if (missing.includes("dex2jar")) skipped.push("DEX-to-JAR conversion");
  // `degraded` drives the UI's "results are not conclusive" banner, so it means
  // "a code-analysis layer is missing", not merely "something isn't installed".
  const degraded = noDisasm;

  return {
    engine: "droidlysis",
    reportVersion: REPORT_VERSION,
    ...meta,
    // Surfaced prominently in the UI: an incomplete run is not a clean result.
    degraded,
    degradedMissing: missing,
    degradedSkipped: skipped,
    // Tools that are absent but didn't cost a code-analysis layer.
    degradedMinor: !noDisasm && skipped.length > 0,
    file: {
      name: raw.sanitized_basename || null,
      type: raw.filetype != null ? String(raw.filetype) : null,
      sizeBytes: raw.file_size || 0,
      classes: raw.file_nb_classes || 0,
      dirs: raw.file_nb_dir || 0,
      small: !!raw.file_small,
      innerZips: !!raw.file_innerzips,
    },
    manifest: {
      package: manifest.package_name || null,
      mainActivity: manifest.main_activity || null,
      minSdk: manifest.minSDK || null,
      targetSdk: manifest.targetSDK || null,
      maxSdk: manifest.maxSDK || null,
      permissions: manifest.permissions || [],
      activities: manifest.activities || [],
      services: manifest.services || [],
      receivers: manifest.receivers || [],
      providers: manifest.providers || [],
      libraries: manifest.libraries || [],
      listensIncomingSms: !!manifest.listens_incoming_sms,
      listensOutgoingCall: !!manifest.listens_outgoing_call,
    },
    // Packed = DroidLysis saw no main activity but dynamic DEX loading. When
    // apktool/baksmali are missing it never parses the manifest or the Smali,
    // so "no main activity" is guaranteed and this flag is a false positive —
    // suppress it rather than report a packer that was never detected.
    packed: degraded ? null : !!smaliProps.packed,
    multidex: Array.isArray(smaliProps.multidex) ? smaliProps.multidex : [],
    strings: {
      appName: wideProps.app_name || null,
      urls: wideProps.urls || [],
      phoneNumbers: wideProps.phonenumbers || [],
      base64: wideProps.base64_strings || [],
      apkZipUrl: !!wideProps.apk_zip_url,
    },
    dex: raw.dex_properties || {},
    kits: kitsFor(raw.kits),
    categories,
    counts: {
      total: allHits.length,
      smali: smali.length,
      wide: wide.length,
      arm: arm.length,
      kits: kitsFor(raw.kits).length,
    },
  };
}

// DroidLysis writes into <out>/<sanitized basename>-<sha256>/report.json.
// We don't recompute the hash — just take the newest matching dir.
function findReportJson(outDir) {
  let entries;
  try { entries = fs.readdirSync(outDir, { withFileTypes: true }); } catch { return null; }
  const dirs = entries.filter(e => e.isDirectory()).map(e => path.join(outDir, e.name));
  let best = null, bestTime = -1;
  for (const d of dirs) {
    const p = path.join(d, "report.json");
    if (!fs.existsSync(p)) continue;
    const t = fs.statSync(p).mtimeMs;
    if (t > bestTime) { best = p; bestTime = t; }
  }
  return best;
}

// Remove DroidLysis' large working files, keeping its reports. Best-effort:
// a failure here costs disk, not correctness.
const KEEP = new Set(["report.json", "report.md", "details.md", "AndroidManifest.xml"]);

function pruneIntermediates(sampleDir, log = () => {}) {
  let freed = 0;
  let entries;
  try { entries = fs.readdirSync(sampleDir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (KEEP.has(e.name)) continue;
    const p = path.join(sampleDir, e.name);
    try {
      if (e.isDirectory()) { freed += dirSize(p); fs.rmSync(p, { recursive: true, force: true }); }
      else { freed += fs.statSync(p).size; fs.rmSync(p, { force: true }); }
    } catch {}
  }
  if (freed > 50 * 1024 * 1024) {
    log(`[droidlysis] cleaned up ${(freed / (1024 * 1024)).toFixed(0)} MB of intermediate ` +
        `unpack/disassembly files (reports kept)`, "sys");
  }
}

function dirSize(dir) {
  let total = 0;
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = path.join(cur, e.name);   // join against the dir we just read
      try {
        if (e.isDirectory()) stack.push(p);
        else total += fs.statSync(p).size;
      } catch {}
    }
  }
  return total;
}

function available() { return !!findDroidlysis(); }

// Return a cached analysis for this job, or null. Lets the UI re-open the tab
// without paying for a second full unpack + disassembly.
function cached(apkPath) {
  const p = cachePathFor(apkPath);
  if (!fs.existsSync(p)) return null;
  try {
    const r = JSON.parse(fs.readFileSync(p, "utf8"));
    if (r.reportVersion !== REPORT_VERSION) return null;  // schema moved on
    return { ...r, cached: true };
  } catch { return null; }
}

/**
 * analyze({ apkPath, log }) -> Promise<report>
 * Runs DroidLysis and returns the shaped report. Throws a user-facing Error
 * (with .code) when the tool is missing or produced nothing usable.
 */
async function analyze({ apkPath, log = () => {} }) {
  const bin = findDroidlysis();
  if (!bin) {
    const err = new Error(
      "DroidLysis not found — install it with `pip3 install droidlysis` (see docs/SETUP.md). " +
      "The Malware analysis tab works without it.");
    err.code = "NO_DROIDLYSIS";
    throw err;
  }

  const outDir = outDirFor(apkPath);
  fs.mkdirSync(outDir, { recursive: true });

  const args = ["--input", apkPath, "--output", outDir, "--verbose"];
  // DroidLysis resolves conf/general.conf relative to the *current directory*
  // by default, which would break when the server runs from anywhere else.
  // Pass the config explicitly whenever we can locate it.
  const conf = findDroidlysisConfig();
  if (conf) args.push("--config", path.join(conf, "general.conf"));

  log(`[droidlysis] ${bin} ${args.join(" ")}`, "sys");
  log("[droidlysis] unpacking + disassembling — this takes a while on large APKs", "sys");

  // DroidLysis degrades silently when its unpacking tools aren't configured:
  // it still writes a report, just a nearly empty one. Say so up front.
  const backends = droidlysisBackends();
  if (backends.missing.length) {
    const confPath = conf ? path.join(conf, "general.conf") : "general.conf";
    // Only apktool/baksmali cost the code analysis; dex2jar alone is minor, so
    // don't cry wolf about skipped disassembly when disassembly will happen.
    const noDisasm = backends.missing.includes("apktool") || backends.missing.includes("baksmali");
    log(noDisasm
      ? `[droidlysis] WARNING: ${backends.missing.join(", ")} not found at the paths in ${confPath} ` +
        `— Smali disassembly and manifest parsing will be SKIPPED, so this run only covers raw strings. ` +
        `A low hit count will mean "not inspected", not "not suspicious". Install them and fix the paths.`
      : `[droidlysis] note: ${backends.missing.join(", ")} not found at the paths in ${confPath} ` +
        `— only the DEX-to-JAR step is skipped; code analysis is unaffected.`,
      "err");
  }

  const ok = await run(bin, args, {
    cwd: outDir,
    timeoutMs: 15 * 60 * 1000,   // hard cap: full unpack of a big APK is slow
    stuckMs: 5 * 60 * 1000,      // but silent for 5 min means it's wedged
    onLine: log,
  });

  const reportPath = findReportJson(outDir);
  if (!reportPath) {
    throw new Error(ok
      ? "DroidLysis finished but wrote no report.json — check the console output above."
      : "DroidLysis failed — check the console output above. Its unpacking tools " +
        "(apktool, baksmali, dex2jar) must be installed and configured in general.conf.");
  }

  let raw;
  try { raw = JSON.parse(fs.readFileSync(reportPath, "utf8")); }
  catch (e) { throw new Error("Could not parse DroidLysis report.json — " + e.message); }

  const report = shapeReport(raw, {
    reportDir: path.dirname(reportPath),
    exitOk: ok,
    confFound: !!conf,
  }, backends);

  // Cache the shaped report next to the raw output.
  try { fs.writeFileSync(cachePathFor(apkPath), JSON.stringify(report)); } catch {}

  // Drop the bulky intermediates. Disassembling a large multi-dex app leaves
  // ~1 GB of Smali, extracted DEX and unzipped resources per job, and we've
  // already extracted everything we render. The report.json and our cached
  // shaped copy stay, so re-opening the tab still works without a re-run.
  // (The Forensic tab's own APK file browser reads the original APK, not this.)
  pruneIntermediates(path.dirname(reportPath), log);

  log(`[droidlysis] ${report.counts.total} properties detected ` +
      `(${report.counts.smali} smali, ${report.counts.wide} wide, ${report.counts.arm} arm), ` +
      `${report.counts.kits} third-party kits`, "sys");

  return { ...report, cached: false };
}

module.exports = { analyze, available, cached, outDirFor, backends: droidlysisBackends };
