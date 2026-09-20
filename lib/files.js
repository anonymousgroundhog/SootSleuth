/**
 * lib/files.js  — APK FILE BROWSER (FORENSIC)
 *
 * Lets an analyst browse the *original* files packed inside an APK — the file
 * tree plus each file's contents — the way `unzip -l` + a viewer would, but with
 * Android's binary formats decoded to something readable:
 *
 *   - AndroidManifest.xml and binary res/*.xml (AXML)  → `aapt2 dump xmltree`
 *   - resources.arsc                                    → `aapt2 dump resources`
 *   - plain-text entries (json/txt/smali/pem/…)         → shown as UTF-8
 *   - binaries (.so/.dex/.png/fonts/…)                  → size + hex head + strings
 *
 * All read-only. Reuses inspector.js's ZIP helpers so the tree and reads come
 * from the same central-directory reader (unzip when present, pure-JS fallback).
 * Nothing is extracted to disk beyond the per-request temp the bundle resolver
 * already uses.
 */

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { findBuildTool, findBin } = require("./tools");
const { listZipEntriesDetailed, extractEntry, resolveBundle } = require("./inspector");

// Extensions we render as text directly from the raw bytes.
const TEXT_EXT = /\.(txt|json|xml|smali|properties|prop|cfg|conf|ini|yml|yaml|md|js|mjs|css|html?|csv|tsv|pem|crt|version|kotlin_module|kotlin_builtins|proto|graphql|sql|sh|gradle|pro|map|storyboard)$/i;
// Extensions that are XML but stored as *binary* AXML inside an APK.
const AXML_ALWAYS = /^AndroidManifest\.xml$/;
// Binary types we describe rather than dump.
const BIN_EXT = /\.(so|dex|arsc|png|jpe?g|gif|webp|bmp|ico|ttf|otf|woff2?|mp[34]|ogg|wav|zip|jar|bin|dat|keystore|jks|pb)$/i;

const HEX_HEAD = 512;      // bytes of hex preview for binaries
const TEXT_MAX = 512 * 1024; // cap for inline text
const STRINGS_SAMPLE = 60;   // printable strings shown for a binary

function aaptBin() { return findBuildTool("aapt2") || findBin("aapt"); }

// ── File tree ─────────────────────────────────────────────────────────────────
// Build a nested tree from the flat ZIP entry list so the frontend can render an
// expandable explorer. Directories are synthesised from the "/" in entry names.
function buildTree(entries, sizes) {
  const root = { name: "", path: "", dir: true, children: {} };
  for (const name of entries) {
    if (!name || name.endsWith("/")) continue;
    const parts = name.split("/");
    let node = root;
    let acc = "";
    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i];
      acc = acc ? acc + "/" + seg : seg;
      const leaf = i === parts.length - 1;
      if (leaf) {
        node.children[seg] = { name: seg, path: name, dir: false, size: sizes[name] ?? null, kind: classify(name) };
      } else {
        node.children[seg] = node.children[seg] || { name: seg, path: acc, dir: true, children: {} };
        node = node.children[seg];
      }
    }
  }
  // Convert children maps → sorted arrays (dirs first, then files, alphabetical).
  const toArr = n => {
    if (!n.dir) return n;
    const kids = Object.values(n.children).map(toArr)
      .sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1));
    return { name: n.name, path: n.path, dir: true, children: kids };
  };
  return toArr(root).children;
}

function classify(name) {
  const base = path.basename(name);
  if (AXML_ALWAYS.test(base)) return "manifest";
  if (/\.arsc$/i.test(name)) return "resources";
  if (/^classes\d*\.dex$/i.test(base)) return "dex";
  if (/\.so$/i.test(name)) return "native";
  if (/\.(png|jpe?g|gif|webp|bmp|ico)$/i.test(name)) return "image";
  if (/\.(ttf|otf|woff2?)$/i.test(name)) return "font";
  if (name.startsWith("META-INF/") && /\.(rsa|dsa|ec|sf|mf)$/i.test(name)) return "signature";
  if (/\.xml$/i.test(name)) return "xml";
  if (TEXT_EXT.test(name)) return "text";
  if (BIN_EXT.test(name)) return "binary";
  return "other";
}

function listApkFiles(outerPath) {
  const bundle = resolveBundle(outerPath);
  const apkPath = bundle && bundle.basePath ? bundle.basePath : outerPath;
  try {
    const detailed = listZipEntriesDetailed(apkPath).filter(e => e.name && !e.name.endsWith("/"));
    const entries = detailed.map(e => e.name);
    const sizes = {};
    for (const e of detailed) sizes[e.name] = e.size;
    return {
      file: path.basename(outerPath),
      entryCount: entries.length,
      tree: buildTree(entries, sizes),
      bundle: bundle && bundle.innerApks
        ? { type: path.extname(outerPath).toLowerCase().replace(".", "") || "bundle", baseApk: bundle.baseName }
        : null,
    };
  } finally {
    if (bundle?.tmpDir) { try { fs.rmSync(bundle.tmpDir, { recursive: true, force: true }); } catch {} }
  }
}

// ── AXML / resources decoding ─────────────────────────────────────────────────
// aapt2/aapt operate on the APK file + an entry path, so we point them at the
// (possibly bundle-extracted) base APK, not at loose bytes.
function decodeXmlTree(apkPath, entryName) {
  const aapt = aaptBin();
  if (!aapt) return null;
  // aapt2 syntax: `aapt2 dump xmltree <apk> --file <entry>`; legacy aapt:
  // `aapt dump xmltree <apk> <entry>`.
  const isAapt2 = /aapt2(\.exe)?$/i.test(aapt);
  const args = isAapt2
    ? ["dump", "xmltree", apkPath, "--file", entryName]
    : ["dump", "xmltree", apkPath, entryName];
  const r = spawnSync(aapt, args, { encoding: "utf8", timeout: 20000, maxBuffer: 32 * 1024 * 1024 });
  const out = (r.stdout || "").trim();
  return out || null;
}

function decodeResources(apkPath) {
  const aapt = aaptBin();
  if (!aapt) return null;
  const isAapt2 = /aapt2(\.exe)?$/i.test(aapt);
  const args = isAapt2 ? ["dump", "resources", apkPath] : ["dump", "--values", "resources", apkPath];
  const r = spawnSync(aapt, args, { encoding: "utf8", timeout: 30000, maxBuffer: 64 * 1024 * 1024 });
  let out = (r.stdout || "").trim();
  if (!out) return null;
  // Resource tables are huge — cap so the browser stays responsive.
  const lines = out.split("\n");
  if (lines.length > 4000) out = lines.slice(0, 4000).join("\n") + `\n… (${lines.length - 4000} more lines truncated)`;
  return out;
}

// Detect binary AXML: magic 0x00080003 (LE) at the start.
function isBinaryAxml(buf) {
  return buf && buf.length >= 4 && buf[0] === 0x03 && buf[1] === 0x00 && buf[2] === 0x08 && buf[3] === 0x00;
}

function hexDump(buf, n) {
  const len = Math.min(buf.length, n);
  const rows = [];
  for (let i = 0; i < len; i += 16) {
    const slice = buf.subarray(i, Math.min(i + 16, len));
    const hex = [...slice].map(b => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const asc = [...slice].map(b => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    rows.push(`${i.toString(16).padStart(8, "0")}  ${hex}  ${asc}`);
  }
  return rows.join("\n");
}

function printableStrings(buf, max) {
  const out = [];
  let cur = "";
  for (let i = 0; i < buf.length && out.length < max; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
    else { if (cur.length >= 4) out.push(cur); cur = ""; }
  }
  if (cur.length >= 4 && out.length < max) out.push(cur);
  return out;
}

// ── Read one file ─────────────────────────────────────────────────────────────
function readApkFile(outerPath, entryName) {
  const bundle = resolveBundle(outerPath);
  const apkPath = bundle && bundle.basePath ? bundle.basePath : outerPath;
  try {
    return readFrom(apkPath, entryName);
  } finally {
    if (bundle?.tmpDir) { try { fs.rmSync(bundle.tmpDir, { recursive: true, force: true }); } catch {} }
  }
}

function readFrom(apkPath, entryName) {
  const base = { path: entryName, kind: classify(entryName) };
  const buf = extractEntry(apkPath, entryName);
  if (buf == null) return { ...base, error: "entry not found or unreadable" };
  base.size = buf.length;

  // resources.arsc → aapt2 resources dump.
  if (/(^|\/)resources\.arsc$/i.test(entryName)) {
    const dec = decodeResources(apkPath);
    return dec
      ? { ...base, format: "resources", content: dec }
      : { ...base, format: "binary", ...binaryView(buf), note: "aapt2/aapt not available to decode resources.arsc" };
  }

  // AndroidManifest.xml or any binary-AXML .xml → decode to a readable tree.
  const isXml = /\.xml$/i.test(entryName);
  if (isXml && (AXML_ALWAYS.test(path.basename(entryName)) || isBinaryAxml(buf))) {
    const tree = decodeXmlTree(apkPath, entryName);
    if (tree) return { ...base, format: "axml", content: tree };
    // Fall through to raw/binary if decode failed.
    return { ...base, format: "binary", ...binaryView(buf), note: "binary AXML; aapt2/aapt not available to decode" };
  }

  // Plain-text (incl. non-binary .xml, e.g. already-decoded or asset XML).
  if (TEXT_EXT.test(entryName) || (isXml && !isBinaryAxml(buf))) {
    if (buf.length > TEXT_MAX) {
      return { ...base, format: "text", truncated: true,
        content: buf.subarray(0, TEXT_MAX).toString("utf8") + `\n… (truncated at ${TEXT_MAX} bytes of ${buf.length})` };
    }
    return { ...base, format: "text", content: buf.toString("utf8") };
  }

  // Everything else → binary description.
  return { ...base, format: "binary", ...binaryView(buf) };
}

function binaryView(buf) {
  return {
    hex: hexDump(buf, HEX_HEAD),
    strings: printableStrings(buf, STRINGS_SAMPLE),
  };
}

module.exports = { listApkFiles, readApkFile };
