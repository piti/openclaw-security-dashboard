// =============================================================================
// BulwarkAI — OpenClaw Security Dashboard: Watcher
// Periodic re-scan with grade history tracking
// =============================================================================

const fs = require('fs');
const path = require('path');
const os = require('os');

const HOME = os.homedir();
const LOG_DIR = path.join(HOME, '.openclaw', '.dashboard-logs');
const HISTORY_FILE = path.join(LOG_DIR, 'grade-history.jsonl');

// Watcher state
let watcherState = {
  active: false,
  intervalMinutes: 30,
  nextScanAt: null,
  lastGrade: null,
  timerId: null,
};

// The scan callback is injected from server.js
let scanCallback = null;

/**
 * Start the periodic watcher.
 * @param {number} intervalMinutes - Minutes between scans (default 30)
 * @param {Function} doScan - Callback that runs a full scan and returns the result.
 *   Must return an object with at least { grade, score, summary: { critical, high, medium, low } }
 */
function startWatcher(intervalMinutes, doScan) {
  if (!doScan || typeof doScan !== 'function') {
    console.error('[!] Watcher requires a scan callback.');
    return;
  }

  scanCallback = doScan;
  const interval = (intervalMinutes && intervalMinutes > 0) ? intervalMinutes : 30;
  watcherState.intervalMinutes = interval;
  watcherState.active = true;

  // Ensure log directory exists
  fs.mkdirSync(LOG_DIR, { recursive: true });

  // Load last grade from history if available
  try {
    if (fs.existsSync(HISTORY_FILE)) {
      const lines = fs.readFileSync(HISTORY_FILE, 'utf8').trim().split('\n').filter(Boolean);
      if (lines.length > 0) {
        const last = JSON.parse(lines[lines.length - 1]);
        watcherState.lastGrade = last.grade || null;
      }
    }
  } catch {}

  const intervalMs = interval * 60 * 1000;
  watcherState.nextScanAt = new Date(Date.now() + intervalMs).toISOString();

  watcherState.timerId = setInterval(() => {
    runWatcherScan();
    watcherState.nextScanAt = new Date(Date.now() + intervalMs).toISOString();
  }, intervalMs);

  const ts = formatTimestamp(new Date());
  console.log(`[${ts}] Watcher started: scanning every ${interval}m`);
}

/**
 * Execute a single watcher scan cycle.
 */
function runWatcherScan() {
  if (!scanCallback) return;

  try {
    const result = scanCallback();
    const now = new Date();
    const ts = formatTimestamp(now);
    const s = result.summary || {};

    const entry = {
      timestamp: now.toISOString(),
      grade: result.grade,
      score: result.score,
      critical: s.critical || 0,
      high: s.high || 0,
      medium: s.medium || 0,
      low: s.low || 0,
    };

    // Append to grade history
    try {
      fs.appendFileSync(HISTORY_FILE, JSON.stringify(entry) + '\n');
    } catch (err) {
      console.error(`[${ts}] Failed to write grade history: ${err.message}`);
    }

    // Log grade change
    const prevGrade = watcherState.lastGrade;
    if (prevGrade && prevGrade !== result.grade) {
      console.log(`[${ts}] Grade changed: ${prevGrade} -> ${result.grade} (score ${result.score})`);
    }

    watcherState.lastGrade = result.grade;
  } catch (err) {
    const ts = formatTimestamp(new Date());
    console.error(`[${ts}] Watcher scan failed: ${err.message}`);
  }
}

/**
 * Get the current watcher state for the /api/watch endpoint.
 */
function getWatcherState() {
  return {
    active: watcherState.active,
    intervalMinutes: watcherState.intervalMinutes,
    nextScanAt: watcherState.nextScanAt,
    lastGrade: watcherState.lastGrade,
  };
}

/**
 * Format a Date as "YYYY-MM-DD HH:MM" for log output.
 */
function formatTimestamp(d) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

module.exports = { startWatcher, getWatcherState };
