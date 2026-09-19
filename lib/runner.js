/**
 * lib/runner.js
 * Spawn subprocesses and stream stdout/stderr line-by-line to a callback.
 * The callback lets server.js push each line over Server-Sent Events to the UI.
 * Adapted from MADPro command-line-tool/lib/runner.js.
 */

const { spawn } = require("child_process");

const SOOT_NOISE_RE = /TypePromotionUseVisitor|Failed Typing in|GC\(\d+\)|gc,start|gc,task|gc,phases|gc,heap|gc,metaspace|gc,cpu|Pause Young|Pause Full|Evacuation Pause|Using \d+ workers/;

function splitLines(buf) {
  const lines = buf.split("\n");
  const remainder = lines.pop();
  return {
    lines: lines.map(l => l.replace(/\r/g, "").trim()).filter(Boolean),
    remainder,
  };
}

/**
 * run(cmd, args, opts) -> Promise<boolean> (true if exit code 0)
 *
 * opts:
 *   cwd        string
 *   timeoutMs  number   hard wall-clock kill (0 = none)
 *   stuckMs    number   kill if no output for N ms (0 = none)
 *   filterSoot boolean  suppress Soot GC noise
 *   filterRe   RegExp   suppress lines matching regex
 *   onLine     (line, stream) => void   stream is "out" | "err" | "sys"
 */
function run(cmd, args, opts = {}) {
  const emit = (line, stream = "out") => {
    if (opts.onLine) opts.onLine(line, stream);
  };

  return new Promise(resolve => {
    let proc;
    try {
      proc = spawn(cmd, args, {
        cwd: opts.cwd || process.cwd(),
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      emit("ERROR: " + err.message, "sys");
      return resolve(false);
    }

    let outBuf = "";
    let errBuf = "";
    let lastOut = Date.now();

    proc.stdout.on("data", d => {
      lastOut = Date.now();
      outBuf += d.toString();
      const { lines, remainder } = splitLines(outBuf);
      outBuf = remainder;
      for (const l of lines) emit(l, "out");
    });

    proc.stderr.on("data", d => {
      lastOut = Date.now();
      errBuf += d.toString();
      const { lines, remainder } = splitLines(errBuf);
      errBuf = remainder;
      for (const l of lines) {
        if (opts.filterSoot && SOOT_NOISE_RE.test(l)) continue;
        if (opts.filterRe && opts.filterRe.test(l)) continue;
        emit(l, "err");
      }
    });

    let killTimer = null;
    let stuckTimer = null;

    if (opts.timeoutMs > 0) {
      killTimer = setTimeout(() => {
        emit(`[TIMEOUT] Killed after ${opts.timeoutMs}ms`, "sys");
        try { proc.kill("SIGTERM"); } catch {}
        setTimeout(() => { try { proc.kill("SIGKILL"); } catch {} }, 5000);
      }, opts.timeoutMs);
    }

    if (opts.stuckMs > 0) {
      stuckTimer = setInterval(() => {
        if (Date.now() - lastOut >= opts.stuckMs) {
          emit(`[TIMEOUT] No output for ${opts.stuckMs / 1000}s — killing`, "sys");
          clearInterval(stuckTimer);
          try { proc.kill("SIGTERM"); } catch {}
        }
      }, Math.min(opts.stuckMs, 5000));
    }

    proc.on("close", code => {
      if (killTimer) clearTimeout(killTimer);
      if (stuckTimer) clearInterval(stuckTimer);
      if (outBuf.trim()) emit(outBuf.trim(), "out");
      if (errBuf.trim()) emit(errBuf.trim(), "err");
      resolve(code === 0);
    });

    proc.on("error", err => {
      if (killTimer) clearTimeout(killTimer);
      if (stuckTimer) clearInterval(stuckTimer);
      emit("ERROR: " + err.message, "sys");
      resolve(false);
    });
  });
}

module.exports = { run };
