/**
 * lib/bundle.js
 * XAPK / .apks bundle handling: unpack to a work dir, and repack a directory
 * of files back into a bundle.
 *
 * A bundle is a plain ZIP containing base.apk + config.*.apk splits + a
 * manifest.json (APKPure XAPK) or similar. Injection must unpack it, inject the
 * base APK, re-sign every APK with one key, then repack.
 *
 * Uses the `unzip`/`zip` CLIs when available (fast); falls back to Node for
 * reading, and a pure-JS STORE-method ZIP writer for repacking so the tool
 * still works on Windows without the Info-ZIP binaries.
 */

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const zlib = require("zlib");
const { findBin } = require("./tools");

const HAVE_UNZIP = !!findBin("unzip");
const HAVE_ZIP   = !!findBin("zip");

function isBundle(file) {
  return /\.(xapk|apks)$/i.test(file);
}

// ── Unpack ───────────────────────────────────────────────────────────────────

function unpack(bundlePath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  if (HAVE_UNZIP) {
    const r = spawnSync("unzip", ["-o", "-q", bundlePath, "-d", destDir], { encoding: "utf8" });
    if (r.status === 0) return;
    // fall through to JS on failure
  }
  unpackJS(bundlePath, destDir);
}

// Pure-JS unpack (STORE + DEFLATE), central-directory based.
function unpackJS(bundlePath, destDir) {
  const buf = fs.readFileSync(bundlePath);
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i > buf.length - 22 - 65536; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a ZIP/bundle");
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count && off + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method   = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen  = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const cmtLen   = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.toString("utf8", off + 46, off + 46 + nameLen);
    off += 46 + nameLen + extraLen + cmtLen;
    if (name.endsWith("/")) { fs.mkdirSync(path.join(destDir, name), { recursive: true }); continue; }

    const lh = localOff;
    const lnameLen  = buf.readUInt16LE(lh + 26);
    const lextraLen = buf.readUInt16LE(lh + 28);
    const dataStart = lh + 30 + lnameLen + lextraLen;
    const comp = buf.subarray(dataStart, dataStart + compSize);
    let data;
    if (method === 0) data = Buffer.from(comp);
    else if (method === 8) data = zlib.inflateRawSync(comp);
    else throw new Error("unsupported zip method " + method);
    const outPath = path.join(destDir, name);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, data);
  }
}

// ── Repack ───────────────────────────────────────────────────────────────────

// Repack the given files (absolute paths) into bundlePath. Entry names are the
// basenames — XAPK/.apks are flat. APKs are already compressed containers, so
// STORE keeps repack fast and lossless.
function repack(bundlePath, files) {
  if (HAVE_ZIP) {
    // zip -0 (store), -j (junk paths → flat), -X (no extra attrs)
    const args = ["-0", "-j", "-X", "-q", bundlePath, ...files];
    const r = spawnSync("zip", args, { encoding: "utf8" });
    if (r.status === 0) return;
  }
  repackJS(bundlePath, files);
}

// Pure-JS STORE-method ZIP writer (flat, no compression).
function repackJS(bundlePath, files) {
  const crcTable = repackJS._crc || (repackJS._crc = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })());
  const crc32 = b => {
    let c = 0xffffffff;
    for (let i = 0; i < b.length; i++) c = crcTable[(c ^ b[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };

  const locals = [];
  const central = [];
  let offset = 0;

  for (const f of files) {
    const name = Buffer.from(path.basename(f), "utf8");
    const data = fs.readFileSync(f);
    const crc = crc32(data);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);            // version needed
    lh.writeUInt16LE(0, 6);             // flags
    lh.writeUInt16LE(0, 8);             // method STORE
    lh.writeUInt16LE(0, 10);            // time
    lh.writeUInt16LE(0, 12);            // date
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);  // comp size
    lh.writeUInt32LE(data.length, 22);  // uncomp size
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);            // extra len
    locals.push(lh, name, data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(0, 10);            // method STORE
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt16LE(0, 30);           // extra
    ch.writeUInt16LE(0, 32);           // comment
    ch.writeUInt16LE(0, 34);           // disk
    ch.writeUInt16LE(0, 36);           // int attr
    ch.writeUInt32LE(0, 38);           // ext attr
    ch.writeUInt32LE(offset, 42);      // local header offset
    central.push(ch, name);

    offset += lh.length + name.length + data.length;
  }

  const localBuf = Buffer.concat(locals);
  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(localBuf.length, 16);
  eocd.writeUInt16LE(0, 20);

  fs.writeFileSync(bundlePath, Buffer.concat([localBuf, centralBuf, eocd]));
}

// Read + rewrite manifest.json's base filename if it changed (kept same here).
function readManifest(dir) {
  const p = path.join(dir, "manifest.json");
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}

// Pick the base APK inside an unpacked bundle dir.
function findBaseApk(dir, manifest) {
  const apks = fs.readdirSync(dir).filter(f => /\.apk$/i.test(f));
  if (!apks.length) return null;
  if (manifest?.split_apks) {
    const base = manifest.split_apks.find(s => s.id === "base");
    if (base && apks.includes(base.file)) return base.file;
  }
  return apks.find(f => f.toLowerCase() === "base.apk")
    || (manifest?.package_name && apks.find(f => f.startsWith(manifest.package_name)))
    || apks.find(f => !/^(config\.|split_config\.)/i.test(f))
    || apks[0];
}

module.exports = { isBundle, unpack, repack, readManifest, findBaseApk, HAVE_ZIP, HAVE_UNZIP };
