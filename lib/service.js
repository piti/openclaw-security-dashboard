// =============================================================================
// BulwarkAI — OpenClaw Security Dashboard: Service Management
// Install/uninstall background service + status/version-check
// =============================================================================

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const https = require('https');

const HOME = os.homedir();
const LOG_DIR = path.join(HOME, '.openclaw', '.dashboard-logs');
const LOG_FILE = path.join(LOG_DIR, 'dashboard.log');
const VERSION_CHECK_FILE = path.join(LOG_DIR, '.version-check');
const PKG = require(path.join(__dirname, '..', 'package.json'));
const CURRENT_VERSION = PKG.version || '1.0.0';
const PORT = parseInt(process.env.SECURITY_DASHBOARD_PORT, 10) || 7177;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function ensureLogDir() {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

/**
 * Resolve the path to the global npm bin for openclaw-security-dashboard.
 * Falls back to the current server.js path.
 */
function resolveBinPath() {
  try {
    const npmBin = execSync('npm bin -g', { encoding: 'utf8' }).trim();
    const candidate = path.join(npmBin, 'openclaw-security-dashboard');
    if (fs.existsSync(candidate)) return candidate;
  } catch {}
  // Fallback: use the absolute path to server.js
  return path.resolve(path.join(__dirname, '..', 'server.js'));
}

/**
 * Compare two dot-separated version strings. Returns:
 *  -1 if a < b, 0 if equal, 1 if a > b
 */
function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}

// -----------------------------------------------------------------------------
// install()
// -----------------------------------------------------------------------------

function install() {
  const platform = process.platform;

  if (platform === 'win32') {
    console.log('');
    console.log('[i] Background service not yet supported on Windows.');
    console.log('    Run `npx openclaw-security-dashboard` in a terminal.');
    console.log('');
    return;
  }

  ensureLogDir();
  const binPath = resolveBinPath();

  if (platform === 'darwin') {
    installMacOS(binPath);
  } else {
    installLinux(binPath);
  }
}

function installMacOS(binPath) {
  const plistDir = path.join(HOME, 'Library', 'LaunchAgents');
  const plistPath = path.join(plistDir, 'io.bulwarkai.dashboard.plist');

  fs.mkdirSync(plistDir, { recursive: true });

  // Determine if binPath is a symlink to node script or a direct executable
  // We need node to run the JS file if it's not a true binary
  const needsNode = binPath.endsWith('.js');
  const programArgs = needsNode
    ? `    <array>
      <string>${process.execPath}</string>
      <string>${binPath}</string>
      <string>--service</string>
    </array>`
    : `    <array>
      <string>${binPath}</string>
      <string>--service</string>
    </array>`;

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.bulwarkai.dashboard</string>
  <key>ProgramArguments</key>
${programArgs}
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_FILE}</string>
  <key>StandardErrorPath</key>
  <string>${LOG_FILE}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
  </dict>
</dict>
</plist>
`;

  fs.writeFileSync(plistPath, plist);

  try {
    // Unload first in case already loaded (ignore errors)
    try { execSync(`launchctl unload ${plistPath}`, { stdio: 'ignore' }); } catch {}
    execSync(`launchctl load ${plistPath}`, { stdio: 'ignore' });
  } catch (err) {
    console.error(`[!] Failed to load LaunchAgent: ${err.message}`);
    console.error(`    Try manually: launchctl load ${plistPath}`);
    return;
  }

  printInstallSuccess(plistPath);
}

function installLinux(binPath) {
  const serviceDir = path.join(HOME, '.config', 'systemd', 'user');
  const servicePath = path.join(serviceDir, 'openclaw-security-dashboard.service');

  fs.mkdirSync(serviceDir, { recursive: true });

  const needsNode = binPath.endsWith('.js');
  const execStart = needsNode
    ? `${process.execPath} ${binPath} --service`
    : `${binPath} --service`;

  const unit = `[Unit]
Description=BulwarkAI OpenClaw Security Dashboard
After=network.target

[Service]
Type=simple
ExecStart=${execStart}
Restart=on-failure
RestartSec=10
Environment=PATH=/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
`;

  fs.writeFileSync(servicePath, unit);

  try {
    execSync('systemctl --user daemon-reload', { stdio: 'ignore' });
    execSync('systemctl --user enable --now openclaw-security-dashboard', { stdio: 'ignore' });
  } catch (err) {
    console.error(`[!] Failed to enable systemd service: ${err.message}`);
    console.error(`    Try manually: systemctl --user enable --now openclaw-security-dashboard`);
    return;
  }

  printInstallSuccess(servicePath);
}

function printInstallSuccess(configPath) {
  console.log('');
  console.log('[OK] Background service installed and started.');
  console.log('');
  console.log(`     Dashboard:  http://localhost:${PORT}`);
  console.log(`     Logs:       ${LOG_FILE}`);
  console.log(`     Config:     ${configPath}`);
  console.log('');
  console.log('     Useful commands:');
  console.log('       openclaw-security-dashboard status     — check if running');
  console.log('       openclaw-security-dashboard uninstall  — stop and remove service');
  console.log('');
}

// -----------------------------------------------------------------------------
// uninstall()
// -----------------------------------------------------------------------------

function uninstall() {
  const platform = process.platform;

  if (platform === 'win32') {
    console.log('[i] No background service to uninstall on Windows.');
    return;
  }

  if (platform === 'darwin') {
    uninstallMacOS();
  } else {
    uninstallLinux();
  }
}

function uninstallMacOS() {
  const plistPath = path.join(HOME, 'Library', 'LaunchAgents', 'io.bulwarkai.dashboard.plist');

  if (!fs.existsSync(plistPath)) {
    console.log('[i] No LaunchAgent found. Nothing to uninstall.');
    return;
  }

  try {
    execSync(`launchctl unload ${plistPath}`, { stdio: 'ignore' });
  } catch {}

  try {
    fs.unlinkSync(plistPath);
  } catch {}

  console.log('');
  console.log('[OK] Background service stopped and removed.');
  console.log(`     Deleted: ${plistPath}`);
  console.log('');
}

function uninstallLinux() {
  const servicePath = path.join(HOME, '.config', 'systemd', 'user', 'openclaw-security-dashboard.service');

  if (!fs.existsSync(servicePath)) {
    console.log('[i] No systemd service found. Nothing to uninstall.');
    return;
  }

  try {
    execSync('systemctl --user disable --now openclaw-security-dashboard', { stdio: 'ignore' });
  } catch {}

  try {
    fs.unlinkSync(servicePath);
  } catch {}

  try {
    execSync('systemctl --user daemon-reload', { stdio: 'ignore' });
  } catch {}

  console.log('');
  console.log('[OK] Background service stopped and removed.');
  console.log(`     Deleted: ${servicePath}`);
  console.log('');
}

// -----------------------------------------------------------------------------
// status()
// -----------------------------------------------------------------------------

function status() {
  const http = require('http');

  const req = http.get(`http://localhost:${PORT}/api/status`, { timeout: 3000 }, (res) => {
    let body = '';
    res.on('data', (chunk) => { body += chunk; });
    res.on('end', () => {
      try {
        const data = JSON.parse(body);
        console.log('');
        console.log(`[OK] Dashboard is running at http://localhost:${PORT}`);
        console.log(`     Grade: ${data.grade}  (${data.score}/100)`);
        const s = data.summary || {};
        const parts = [];
        if (s.critical > 0) parts.push(`${s.critical} critical`);
        if (s.high > 0) parts.push(`${s.high} high`);
        if (s.medium > 0) parts.push(`${s.medium} medium`);
        if (s.low > 0) parts.push(`${s.low} low`);
        console.log(`     Findings: ${parts.length > 0 ? parts.join(' / ') : 'None'}`);

        // Try to get watcher state
        const watchReq = http.get(`http://localhost:${PORT}/api/watch`, { timeout: 2000 }, (wRes) => {
          let wBody = '';
          wRes.on('data', (c) => { wBody += c; });
          wRes.on('end', () => {
            try {
              const w = JSON.parse(wBody);
              if (w.active) {
                console.log(`     Watch: every ${w.intervalMinutes}m (next scan: ${w.nextScanAt || 'unknown'})`);
                if (w.lastGrade) console.log(`     Last grade: ${w.lastGrade}`);
              } else {
                console.log('     Watch: off');
              }
            } catch {}
            console.log('');
            checkForUpdates();
          });
        });
        watchReq.on('error', () => {
          console.log('');
          checkForUpdates();
        });
      } catch {
        console.log(`[i] Dashboard responded but returned unexpected data.`);
        console.log('');
        checkForUpdates();
      }
    });
  });

  req.on('error', () => {
    console.log('');
    console.log('[--] Dashboard is not running.');
    console.log('');
    console.log('     To start:');
    console.log('       npx openclaw-security-dashboard');
    console.log('');
    console.log('     For always-on monitoring:');
    console.log('       npm i -g openclaw-security-dashboard && openclaw-security-dashboard install');
    console.log('');
    checkForUpdates();
  });

  req.on('timeout', () => {
    req.destroy();
  });
}

// -----------------------------------------------------------------------------
// Version check (cached once per day)
// -----------------------------------------------------------------------------

function checkForUpdates() {
  ensureLogDir();

  // Check cache
  try {
    if (fs.existsSync(VERSION_CHECK_FILE)) {
      const cached = JSON.parse(fs.readFileSync(VERSION_CHECK_FILE, 'utf8'));
      const age = Date.now() - (cached.timestamp || 0);
      if (age < 86400000) { // 24 hours
        if (cached.latest && compareVersions(CURRENT_VERSION, cached.latest) < 0) {
          console.log(`     Update available: ${CURRENT_VERSION} -> ${cached.latest}`);
          console.log('     Run: npm i -g openclaw-security-dashboard');
          console.log('');
        }
        return;
      }
    }
  } catch {}

  // Fetch latest version from npm
  const req = https.get('https://registry.npmjs.org/openclaw-security-dashboard/latest', {
    timeout: 5000,
    headers: { 'Accept': 'application/json' },
  }, (res) => {
    let body = '';
    res.on('data', (chunk) => { body += chunk; });
    res.on('end', () => {
      try {
        const data = JSON.parse(body);
        const latest = data.version;
        // Cache the result
        try {
          fs.writeFileSync(VERSION_CHECK_FILE, JSON.stringify({ timestamp: Date.now(), latest }));
        } catch {}
        if (latest && compareVersions(CURRENT_VERSION, latest) < 0) {
          console.log(`     Update available: ${CURRENT_VERSION} -> ${latest}`);
          console.log('     Run: npm i -g openclaw-security-dashboard');
          console.log('');
        }
      } catch {}
    });
  });

  req.on('error', () => {}); // Silently skip
  req.on('timeout', () => { req.destroy(); });
}

module.exports = { install, uninstall, status };
