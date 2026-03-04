#!/usr/bin/env node

// =============================================================================
// BulwarkAI — OpenClaw Security Dashboard Server
// Zero-dependency Node.js HTTP server for scanning OpenClaw deployments
// =============================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const os = require('os');

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

const PORT = parseInt(process.env.SECURITY_DASHBOARD_PORT, 10) || 7177;
const HOME = os.homedir();

// Identity files tracked for integrity monitoring
const IDENTITY_FILES = ['SOUL.md', 'AGENTS.md', 'USER.md', 'TOOLS.md'];
const BASELINE_FILE = '.bulwarkai-baseline';

// Injection patterns used in identity and session scanning
const INJECTION_PATTERNS = [
  /ignore\s+previous/i,
  /disregard\s+above/i,
  /you\s+are\s+now/i,
  /new\s+instructions/i,
  /<\|im_start\|>/,
  /\[INST\]/,
  /system\s+prompt\s+override/i,
];

// API key patterns that should never appear in config files
const API_KEY_PATTERNS = [
  /sk-[a-zA-Z0-9]{20,}/,
  /sk-ant-[a-zA-Z0-9-]{20,}/,
  /sk-proj-[a-zA-Z0-9-]{20,}/,
  /key-[a-zA-Z0-9]{20,}/,
  /ghp_[a-zA-Z0-9]{36}/,
  /gho_[a-zA-Z0-9]{36}/,
  /xoxb-[0-9]{10,}-[a-zA-Z0-9]{20,}/,
  /AKIA[0-9A-Z]{16}/,
];

// Placeholder patterns indicating incomplete configuration
const PLACEHOLDER_PATTERN = /YOUR_[A-Z_]+/;

// Base64 detection (40+ chars)
const BASE64_PATTERN = /[A-Za-z0-9+/]{40,}={0,2}/;

// Trusted URL domains for skill supply chain checks
const TRUSTED_DOMAINS = ['github.com/openclaw', 'docs.openclaw.ai'];

// URL extraction pattern
const URL_PATTERN = /https?:\/\/[^\s)"']+/g;

// -----------------------------------------------------------------------------
// Global State
// -----------------------------------------------------------------------------

let cachedScanResult = null;
let openclawDir = null;
let iocDatabase = { skills: [] };
let credentialPatterns = [];

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/**
 * Safely read a file, returning null if it doesn't exist or can't be read.
 */
function safeReadFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Safely parse JSON, returning null on failure.
 */
function safeParseJSON(str) {
  if (!str) return null;
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

/**
 * Safely stat a file, returning null if it doesn't exist.
 */
function safeStat(filePath) {
  try {
    return fs.statSync(filePath);
  } catch {
    return null;
  }
}

/**
 * Safely list a directory, returning an empty array on failure.
 */
function safeReaddir(dirPath) {
  try {
    return fs.readdirSync(dirPath);
  } catch {
    return [];
  }
}

/**
 * Compute SHA-256 hash of file contents.
 */
function hashFile(filePath) {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch {
    return null;
  }
}

/**
 * Execute a shell command silently, returning stdout or null on error.
 */
function safeExec(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return null;
  }
}

/**
 * Determine panel status from its findings list.
 * red = any CRITICAL, amber = any HIGH or MEDIUM, green = only LOW or clean.
 */
function panelStatus(findings) {
  if (findings.some(f => f.severity === 'CRITICAL')) return 'red';
  if (findings.some(f => f.severity === 'HIGH' || f.severity === 'MEDIUM')) return 'amber';
  return 'green';
}

/**
 * Recursively find files matching a name within a directory tree.
 */
function findFilesRecursive(dir, targetName, results = []) {
  const entries = safeReaddir(dir);
  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    const stat = safeStat(fullPath);
    if (!stat) continue;
    if (stat.isDirectory()) {
      findFilesRecursive(fullPath, targetName, results);
    } else if (entry === targetName) {
      results.push(fullPath);
    }
  }
  return results;
}

// -----------------------------------------------------------------------------
// OpenClaw Directory Detection
// -----------------------------------------------------------------------------

function detectOpenClawDir() {
  const candidates = [
    process.env.OPENCLAW_DIR,
    path.join(HOME, '.openclaw'),
    '/root/.openclaw',
  ].filter(Boolean);

  for (const dir of candidates) {
    const stat = safeStat(dir);
    if (stat && stat.isDirectory()) {
      return dir;
    }
  }
  return null;
}

// -----------------------------------------------------------------------------
// IOC & Credential Pattern Loading
// -----------------------------------------------------------------------------

function loadIOCDatabase() {
  const iocPath = path.join(__dirname, 'ioc', 'malicious-skills.json');
  const data = safeParseJSON(safeReadFile(iocPath));
  if (data && Array.isArray(data)) {
    iocDatabase.skills = data;
  } else if (data && Array.isArray(data.skills)) {
    iocDatabase.skills = data.skills;
  } else {
    iocDatabase.skills = [];
  }
  return iocDatabase.skills.length;
}

function loadCredentialPatterns() {
  const cpPath = path.join(__dirname, 'ioc', 'credential-patterns.json');
  const data = safeParseJSON(safeReadFile(cpPath));
  const patterns = Array.isArray(data) ? data : (data && Array.isArray(data.api_key_patterns) ? data.api_key_patterns : []);
  credentialPatterns = patterns.map(p => {
    if (typeof p === 'string') {
      try { return new RegExp(p, 'i'); } catch { return null; }
    }
    if (p && p.pattern) {
      try { return new RegExp(p.pattern, p.flags || 'i'); } catch { return null; }
    }
    return null;
  }).filter(Boolean);
  return credentialPatterns.length;
}

// -----------------------------------------------------------------------------
// Panel 1: Gateway Security
// -----------------------------------------------------------------------------

function scanGateway() {
  const checks = [];
  const findings = [];

  if (!openclawDir) {
    return { status: 'red', title: 'Gateway Security', checks, findings };
  }

  // Read openclaw.json
  const configPath = path.join(openclawDir, 'openclaw.json');
  const config = safeParseJSON(safeReadFile(configPath));

  if (!config) {
    findings.push({
      severity: 'HIGH',
      check: 'Configuration file',
      detail: 'openclaw.json not found or invalid JSON',
      remediation: 'Ensure openclaw.json exists in your OpenClaw directory and contains valid JSON.',
    });
    return { status: panelStatus(findings), title: 'Gateway Security', checks, findings };
  }

  const gw = config.gateway || {};

  // Check bind address
  if (gw.bind === '0.0.0.0') {
    findings.push({
      severity: 'CRITICAL',
      check: 'Gateway bind address',
      detail: `Gateway is bound to 0.0.0.0 — exposed to all network interfaces`,
      remediation: 'Set gateway.bind to "127.0.0.1" to restrict access to localhost only.',
    });
  } else if (['127.0.0.1', 'loopback', 'localhost'].includes(gw.bind)) {
    checks.push({
      status: 'clean',
      check: 'Gateway bind address',
      detail: `Gateway bound to ${gw.bind} (loopback only)`,
    });
  } else if (gw.bind) {
    findings.push({
      severity: 'MEDIUM',
      check: 'Gateway bind address',
      detail: `Gateway bound to non-standard address: ${gw.bind}`,
      remediation: 'Verify this bind address is intentional. Prefer 127.0.0.1 for local-only access.',
    });
  }

  // Check auth
  if (!gw.auth) {
    findings.push({
      severity: 'HIGH',
      check: 'Gateway authentication',
      detail: 'Gateway authentication is disabled or not configured',
      remediation: 'Enable gateway.auth in openclaw.json to require authentication for all API calls.',
    });
  } else {
    checks.push({
      status: 'clean',
      check: 'Gateway authentication',
      detail: 'Authentication is enabled on the gateway',
    });
  }

  // Check TLS
  if (gw.tls || gw.ssl || gw.https) {
    checks.push({
      status: 'clean',
      check: 'TLS configuration',
      detail: 'TLS/SSL is configured on the gateway',
    });
  } else {
    findings.push({
      severity: 'MEDIUM',
      check: 'TLS configuration',
      detail: 'No TLS/SSL configuration found in gateway settings',
      remediation: 'Configure TLS in the gateway section to encrypt traffic.',
    });
  }

  // Count devices
  let deviceCount = 0;
  if (Array.isArray(gw.devices)) {
    deviceCount = gw.devices.length;
  }
  const devicesDir = path.join(openclawDir, 'devices');
  const devicesDirEntries = safeReaddir(devicesDir);
  if (devicesDirEntries.length > 0) {
    deviceCount = Math.max(deviceCount, devicesDirEntries.length);
  }
  checks.push({
    status: 'clean',
    check: 'Device inventory',
    detail: `${deviceCount} device(s) registered`,
  });

  // OpenClaw version
  const version = safeExec('openclaw --version');
  if (version) {
    checks.push({
      status: 'clean',
      check: 'OpenClaw version',
      detail: `Running version: ${version}`,
    });
  }

  // Port binding check
  const portCheck = safeExec('lsof -iTCP:18789 -sTCP:LISTEN -nP');
  if (portCheck) {
    checks.push({
      status: 'clean',
      check: 'Port 18789 listener',
      detail: `Gateway port is active: ${portCheck.split('\n')[0]}`,
    });
  }

  return { status: panelStatus(findings), title: 'Gateway Security', checks, findings };
}

// -----------------------------------------------------------------------------
// Panel 2: Skill Supply Chain
// -----------------------------------------------------------------------------

function scanSkills() {
  const checks = [];
  const findings = [];

  if (!openclawDir) {
    return { status: 'green', title: 'Skill Supply Chain', checks, findings };
  }

  // Gather skills from skills/ directory
  const skillsDir = path.join(openclawDir, 'skills');
  const skillEntries = safeReaddir(skillsDir);
  const skillNames = [];

  for (const entry of skillEntries) {
    const fullPath = path.join(skillsDir, entry);
    const stat = safeStat(fullPath);
    if (stat && stat.isDirectory()) {
      skillNames.push({ name: entry, dir: fullPath });
    }
  }

  // Gather project-level skills from workspace/ via SKILL.md
  const workspaceDir = path.join(openclawDir, 'workspace');
  const skillMdFiles = findFilesRecursive(workspaceDir, 'SKILL.md');
  for (const skillMdPath of skillMdFiles) {
    const skillDir = path.dirname(skillMdPath);
    const skillName = path.basename(skillDir);
    if (!skillNames.find(s => s.dir === skillDir)) {
      skillNames.push({ name: skillName, dir: skillDir });
    }
  }

  if (skillNames.length === 0) {
    checks.push({
      status: 'clean',
      check: 'Skill inventory',
      detail: 'No skills installed',
    });
    return { status: 'green', title: 'Skill Supply Chain', checks, findings };
  }

  checks.push({
    status: 'clean',
    check: 'Skill inventory',
    detail: `${skillNames.length} skill(s) found`,
  });

  // IOC name list (lowercase for comparison)
  const maliciousNames = iocDatabase.skills.map(s =>
    (typeof s === 'string' ? s : s.name || '').toLowerCase()
  );

  for (const skill of skillNames) {
    // Cross-reference against IOC database
    if (maliciousNames.includes(skill.name.toLowerCase())) {
      findings.push({
        severity: 'CRITICAL',
        check: 'Malicious skill detected',
        detail: `Skill "${skill.name}" matches known malicious skill in IOC database`,
        remediation: `Remove the skill directory: rm -rf ${skill.dir}`,
      });
      continue;
    }

    // Check SKILL.md content
    const skillMdPath = path.join(skill.dir, 'SKILL.md');
    const skillMd = safeReadFile(skillMdPath);
    if (skillMd) {
      // ClawHavoc ClickFix: prerequisites-style header AND download/exec commands
      const hasPrereqHeader = /^#+\s*(prerequisites?|requirements?|setup|install)/im.test(skillMd);
      const hasExecCmd = /(curl|wget|bash|sh\s|\.\/|exec|eval|child_process|spawn)/i.test(skillMd);
      if (hasPrereqHeader && hasExecCmd) {
        findings.push({
          severity: 'CRITICAL',
          check: 'ClawHavoc ClickFix pattern',
          detail: `Skill "${skill.name}" SKILL.md contains a prerequisites header with download/exec commands — possible ClickFix social engineering`,
          remediation: `Review ${skillMdPath} carefully. Remove the skill if the commands are suspicious.`,
        });
      }

      // External URLs not from trusted domains
      const urls = skillMd.match(URL_PATTERN) || [];
      for (const url of urls) {
        const isTrusted = TRUSTED_DOMAINS.some(d => url.includes(d));
        if (!isTrusted) {
          findings.push({
            severity: 'MEDIUM',
            check: 'External URL in skill',
            detail: `Skill "${skill.name}" references external URL: ${url}`,
            remediation: 'Verify this URL is legitimate and necessary for the skill.',
          });
          break; // One finding per skill for external URLs
        }
      }

      // Base64 strings
      if (BASE64_PATTERN.test(skillMd)) {
        findings.push({
          severity: 'HIGH',
          check: 'Encoded payload in skill',
          detail: `Skill "${skill.name}" contains a Base64-encoded string (40+ chars)`,
          remediation: 'Decode and inspect the Base64 content. Remove if suspicious.',
        });
      }
    }

    // Check for executable files in skill directory
    const skillFiles = safeReaddir(skill.dir);
    for (const file of skillFiles) {
      const ext = path.extname(file).toLowerCase();
      if (['.md', '.txt', '.json'].includes(ext)) continue;
      const filePath = path.join(skill.dir, file);
      const stat = safeStat(filePath);
      if (stat && stat.isFile()) {
        // Check if file is executable
        try {
          fs.accessSync(filePath, fs.constants.X_OK);
          findings.push({
            severity: 'HIGH',
            check: 'Executable in skill directory',
            detail: `Skill "${skill.name}" contains executable file: ${file}`,
            remediation: `Review and remove if not needed: ${filePath}`,
          });
          break; // One finding per skill for executables
        } catch {
          // Not executable — fine
        }
      }
    }
  }

  return { status: panelStatus(findings), title: 'Skill Supply Chain', checks, findings };
}

// -----------------------------------------------------------------------------
// Panel 3: Config Hardening
// -----------------------------------------------------------------------------

function scanConfig() {
  const checks = [];
  const findings = [];

  if (!openclawDir) {
    return { status: 'green', title: 'Config Hardening', checks, findings };
  }

  const configPath = path.join(openclawDir, 'openclaw.json');

  // Check openclaw.json file permissions
  const configStat = safeStat(configPath);
  if (configStat) {
    const mode = configStat.mode & 0o777;
    if (mode === 0o600) {
      checks.push({
        status: 'clean',
        check: 'Config file permissions',
        detail: `openclaw.json permissions are 0600 (owner read/write only)`,
      });
    } else {
      findings.push({
        severity: 'MEDIUM',
        check: 'Config file permissions',
        detail: `openclaw.json has permissions 0${mode.toString(8)} (expected 0600)`,
        remediation: 'Run: chmod 600 openclaw.json',
      });
    }
  }

  // Check credentials/ directory permissions
  const credsDir = path.join(openclawDir, 'credentials');
  const credsStat = safeStat(credsDir);
  if (credsStat && credsStat.isDirectory()) {
    const credsDirMode = credsStat.mode & 0o777;
    if (credsDirMode === 0o700) {
      checks.push({
        status: 'clean',
        check: 'Credentials directory permissions',
        detail: 'credentials/ directory permissions are 0700',
      });
    } else {
      findings.push({
        severity: 'HIGH',
        check: 'Credentials directory permissions',
        detail: `credentials/ has permissions 0${credsDirMode.toString(8)} (expected 0700)`,
        remediation: 'Run: chmod 700 credentials/',
      });
    }

    // Check individual credential files
    const credFiles = safeReaddir(credsDir);
    for (const file of credFiles) {
      const filePath = path.join(credsDir, file);
      const fileStat = safeStat(filePath);
      if (fileStat && fileStat.isFile()) {
        const fileMode = fileStat.mode & 0o777;
        if (fileMode !== 0o600) {
          findings.push({
            severity: 'HIGH',
            check: 'Credential file permissions',
            detail: `credentials/${file} has permissions 0${fileMode.toString(8)} (expected 0600)`,
            remediation: `Run: chmod 600 credentials/${file}`,
          });
        }
      }
    }
  }

  // Scan openclaw.json content for API key patterns
  const configContent = safeReadFile(configPath);
  if (configContent) {
    for (const pattern of API_KEY_PATTERNS) {
      const match = configContent.match(pattern);
      if (match) {
        findings.push({
          severity: 'CRITICAL',
          check: 'API key in configuration',
          detail: `Found API key pattern in openclaw.json: ${match[0].substring(0, 8)}...`,
          remediation: 'Move API keys to environment variables or the credentials/ directory. Never store them in openclaw.json.',
        });
      }
    }

    // Check for placeholder patterns
    const placeholders = configContent.match(new RegExp(PLACEHOLDER_PATTERN.source, 'g'));
    if (placeholders) {
      findings.push({
        severity: 'CRITICAL',
        check: 'Placeholder values in configuration',
        detail: `Found placeholder values in openclaw.json: ${[...new Set(placeholders)].join(', ')}`,
        remediation: 'Replace all YOUR_* placeholder values with actual configuration values.',
      });
    }

    // Check for sandbox/exec settings
    const config = safeParseJSON(configContent);
    if (config) {
      if (config.sandbox === false || config.sandbox?.enabled === false) {
        findings.push({
          severity: 'HIGH',
          check: 'Sandbox disabled',
          detail: 'Sandbox execution is disabled in configuration',
          remediation: 'Enable sandbox mode to isolate skill execution.',
        });
      } else if (config.sandbox) {
        checks.push({
          status: 'clean',
          check: 'Sandbox configuration',
          detail: 'Sandbox execution is enabled',
        });
      }

      if (config.exec?.allow_all === true || config.exec?.unrestricted === true) {
        findings.push({
          severity: 'HIGH',
          check: 'Unrestricted execution',
          detail: 'Execution policy allows unrestricted command execution',
          remediation: 'Restrict exec permissions to specific allowed commands.',
        });
      }
    }

    if (findings.filter(f => f.check.includes('API key') || f.check.includes('Placeholder')).length === 0) {
      checks.push({
        status: 'clean',
        check: 'Secret scanning',
        detail: 'No API keys or placeholder values found in openclaw.json',
      });
    }
  }

  return { status: panelStatus(findings), title: 'Config Hardening', checks, findings };
}

// -----------------------------------------------------------------------------
// Panel 4: Identity Integrity
// -----------------------------------------------------------------------------

function scanIdentity() {
  const checks = [];
  const findings = [];

  if (!openclawDir) {
    return { status: 'green', title: 'Identity Integrity', checks, findings };
  }

  const workspaceDir = path.join(openclawDir, 'workspace');
  const baselinePath = path.join(openclawDir, BASELINE_FILE);

  // Check for identity files
  const currentHashes = {};
  const foundFiles = [];

  for (const file of IDENTITY_FILES) {
    const filePath = path.join(workspaceDir, file);
    const hash = hashFile(filePath);
    if (hash) {
      currentHashes[file] = hash;
      foundFiles.push(file);
    }
  }

  if (foundFiles.length === 0) {
    checks.push({
      status: 'clean',
      check: 'Identity files',
      detail: 'No identity files found in workspace/',
    });
    return { status: 'green', title: 'Identity Integrity', checks, findings };
  }

  checks.push({
    status: 'clean',
    check: 'Identity files',
    detail: `Found ${foundFiles.length} identity file(s): ${foundFiles.join(', ')}`,
  });

  // Load baseline
  const baselineData = safeParseJSON(safeReadFile(baselinePath));

  if (!baselineData) {
    // No baseline exists — create findings as LOW and auto-create baseline
    for (const file of foundFiles) {
      findings.push({
        severity: 'LOW',
        check: 'No baseline for identity file',
        detail: `${file} has no integrity baseline — creating initial baseline now`,
        remediation: 'Baseline has been auto-created. Future changes will be detected.',
      });
    }
    // Auto-create baseline
    try {
      fs.writeFileSync(baselinePath, JSON.stringify(currentHashes, null, 2));
    } catch {
      // Silently fail if we can't write
    }
  } else {
    // Compare hashes against baseline
    for (const file of foundFiles) {
      if (!baselineData[file]) {
        findings.push({
          severity: 'MEDIUM',
          check: 'New identity file',
          detail: `${file} exists but has no baseline entry — may have been added after initial setup`,
          remediation: 'Review the file and accept the new baseline via /api/baseline/accept',
        });
      } else if (baselineData[file] !== currentHashes[file]) {
        findings.push({
          severity: 'HIGH',
          check: 'Identity file modified',
          detail: `${file} hash has changed since baseline was established`,
          remediation: 'Review the changes. If legitimate, accept the new baseline via /api/baseline/accept',
        });
      } else {
        checks.push({
          status: 'clean',
          check: `${file} integrity`,
          detail: `Hash matches baseline`,
        });
      }
    }

    // Check for deleted files that were in baseline
    for (const file of Object.keys(baselineData)) {
      if (!currentHashes[file]) {
        findings.push({
          severity: 'HIGH',
          check: 'Identity file removed',
          detail: `${file} was in the baseline but no longer exists`,
          remediation: 'Investigate why the identity file was removed.',
        });
      }
    }
  }

  // Scan identity files for injection patterns
  for (const file of foundFiles) {
    const filePath = path.join(workspaceDir, file);
    const content = safeReadFile(filePath);
    if (!content) continue;

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          severity: 'CRITICAL',
          check: 'Prompt injection in identity file',
          detail: `${file} contains injection pattern: ${pattern.source}`,
          remediation: `Review and sanitize ${filePath} immediately. This may indicate a prompt injection attack.`,
        });
        break; // One finding per file for injections
      }
    }
  }

  return { status: panelStatus(findings), title: 'Identity Integrity', checks, findings };
}

// -----------------------------------------------------------------------------
// Panel 5: Persistence & Cron
// -----------------------------------------------------------------------------

function scanPersistence() {
  const checks = [];
  const findings = [];

  if (!openclawDir) {
    return { status: 'green', title: 'Persistence & Cron', checks, findings };
  }

  // Check cron/jobs.json
  const cronJobsPath = path.join(openclawDir, 'cron', 'jobs.json');
  const cronJobs = safeParseJSON(safeReadFile(cronJobsPath));
  if (cronJobs) {
    const jobCount = Array.isArray(cronJobs) ? cronJobs.length : Object.keys(cronJobs).length;
    checks.push({
      status: 'clean',
      check: 'Cron jobs',
      detail: `${jobCount} cron job(s) configured in cron/jobs.json`,
    });
  }

  // Check system crontab for openclaw entries
  const crontab = safeExec('crontab -l');
  if (crontab) {
    const lines = crontab.split('\n');
    for (const line of lines) {
      if (/openclaw|clawdbot/i.test(line)) {
        findings.push({
          severity: 'LOW',
          check: 'System crontab entry',
          detail: `Found OpenClaw-related crontab entry: ${line.trim()}`,
          remediation: 'Review this crontab entry to ensure it is expected.',
        });
      }
    }
  }

  // Check LaunchAgents (macOS)
  const launchAgentsDir = path.join(HOME, 'Library', 'LaunchAgents');
  const launchAgents = safeReaddir(launchAgentsDir);
  for (const plist of launchAgents) {
    if (!plist.endsWith('.plist')) continue;
    const plistContent = safeReadFile(path.join(launchAgentsDir, plist));
    if (plistContent && /openclaw/i.test(plistContent)) {
      findings.push({
        severity: 'LOW',
        check: 'LaunchAgent detected',
        detail: `LaunchAgent plist references OpenClaw: ${plist}`,
        remediation: 'Review this LaunchAgent to ensure it is expected and authorized.',
      });
    }
  }

  // Check hooks/ directories
  const hooksDir = path.join(openclawDir, 'hooks');
  const hookEntries = safeReaddir(hooksDir);
  const hookMdFiles = hookEntries.filter(e => {
    const hookSubDir = path.join(hooksDir, e);
    const stat = safeStat(hookSubDir);
    if (stat && stat.isDirectory()) {
      return safeReaddir(hookSubDir).includes('HOOK.md');
    }
    return e === 'HOOK.md';
  });

  if (hookMdFiles.length > 0) {
    findings.push({
      severity: 'MEDIUM',
      check: 'Hook definitions',
      detail: `Found ${hookMdFiles.length} hook definition(s) in hooks/ directory`,
      remediation: 'Review all hook definitions to ensure they perform expected actions.',
    });
  }

  // Check mcp.json
  const mcpPath = path.join(openclawDir, 'mcp.json');
  const mcpConfig = safeParseJSON(safeReadFile(mcpPath));
  if (mcpConfig) {
    const servers = mcpConfig.servers || mcpConfig.mcpServers || {};
    const serverCount = Object.keys(servers).length;
    checks.push({
      status: 'clean',
      check: 'MCP servers',
      detail: `${serverCount} MCP server(s) configured`,
    });

    // Check for unpinned versions
    for (const [name, config] of Object.entries(servers)) {
      const version = config.version || config.tag || '';
      if (version === 'latest' || version === '*') {
        findings.push({
          severity: 'HIGH',
          check: 'Unpinned MCP server version',
          detail: `MCP server "${name}" uses unpinned version: ${version}`,
          remediation: `Pin the version of MCP server "${name}" to a specific release.`,
        });
      }
    }
  }

  if (findings.length === 0 && checks.length === 0) {
    checks.push({
      status: 'clean',
      check: 'Persistence mechanisms',
      detail: 'No persistence mechanisms detected',
    });
  }

  return { status: panelStatus(findings), title: 'Persistence & Cron', checks, findings };
}

// -----------------------------------------------------------------------------
// Panel 6: Session Analysis
// -----------------------------------------------------------------------------

function scanSessions() {
  const checks = [];
  const findings = [];

  if (!openclawDir) {
    return { status: 'green', title: 'Session Analysis', checks, findings };
  }

  const sessionsDir = path.join(openclawDir, 'sessions');
  const sessionFiles = safeReaddir(sessionsDir).filter(f => f.endsWith('.jsonl'));

  if (sessionFiles.length === 0) {
    checks.push({
      status: 'clean',
      check: 'Session files',
      detail: 'No session log files found',
    });
    return { status: 'green', title: 'Session Analysis', checks, findings };
  }

  const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
  let recentCount = 0;
  let scannedCount = 0;

  for (const file of sessionFiles) {
    const filePath = path.join(sessionsDir, file);
    const stat = safeStat(filePath);
    if (!stat || stat.mtimeMs < thirtyDaysAgo) continue;

    recentCount++;
    const content = safeReadFile(filePath);
    if (!content) continue;
    scannedCount++;

    // Check for injection patterns
    let injectionFound = false;
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          severity: 'HIGH',
          check: 'Injection pattern in session',
          detail: `Session file ${file} contains injection pattern: ${pattern.source}`,
          remediation: `Review session log ${filePath} for prompt injection attempts.`,
        });
        injectionFound = true;
        break;
      }
    }

    // Check for credential patterns
    if (!injectionFound) {
      for (const pattern of credentialPatterns) {
        if (pattern.test(content)) {
          findings.push({
            severity: 'HIGH',
            check: 'Credential leak in session',
            detail: `Session file ${file} contains credential pattern`,
            remediation: `Review and sanitize session log ${filePath}. Rotate any exposed credentials.`,
          });
          break;
        }
      }
    }

    // Also check for API key patterns as fallback if no credential-patterns.json loaded
    if (credentialPatterns.length === 0) {
      for (const pattern of API_KEY_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            severity: 'HIGH',
            check: 'Credential in session log',
            detail: `Session file ${file} contains an API key pattern`,
            remediation: `Review and sanitize ${filePath}. Rotate the exposed credential.`,
          });
          break;
        }
      }
    }
  }

  checks.push({
    status: 'clean',
    check: 'Session files scanned',
    detail: `Scanned ${scannedCount} of ${recentCount} recent session file(s) (last 30 days)`,
  });

  return { status: panelStatus(findings), title: 'Session Analysis', checks, findings };
}

// -----------------------------------------------------------------------------
// Grade Calculation
// -----------------------------------------------------------------------------

function calculateGrade(summary) {
  let score = 100;
  score -= summary.critical * 25;
  score -= summary.high * 15;
  score -= summary.medium * 5;
  score -= summary.low * 2;
  score = Math.max(0, score);

  const gradeTable = [
    [97, 'A+'], [93, 'A'], [90, 'A-'],
    [87, 'B+'], [83, 'B'], [80, 'B-'],
    [77, 'C+'], [73, 'C'], [70, 'C-'],
    [67, 'D+'], [63, 'D'], [60, 'D-'],
  ];

  let grade = 'F';
  for (const [threshold, letter] of gradeTable) {
    if (score >= threshold) {
      grade = letter;
      break;
    }
  }

  let gradeColor;
  if (grade.startsWith('A')) gradeColor = '#22c55e';
  else if (grade.startsWith('B')) gradeColor = '#3b82f6';
  else if (grade.startsWith('C')) gradeColor = '#f59e0b';
  else if (grade.startsWith('D')) gradeColor = '#f97316';
  else gradeColor = '#ef4444';

  return { grade, score, gradeColor };
}

// -----------------------------------------------------------------------------
// Full Scan Orchestrator
// -----------------------------------------------------------------------------

function runFullScan() {
  const gateway = scanGateway();
  const skills = scanSkills();
  const config = scanConfig();
  const identity = scanIdentity();
  const persistence = scanPersistence();
  const sessions = scanSessions();

  const allFindings = [
    ...gateway.findings,
    ...skills.findings,
    ...config.findings,
    ...identity.findings,
    ...persistence.findings,
    ...sessions.findings,
  ];

  const summary = {
    critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
    high: allFindings.filter(f => f.severity === 'HIGH').length,
    medium: allFindings.filter(f => f.severity === 'MEDIUM').length,
    low: allFindings.filter(f => f.severity === 'LOW').length,
    total: allFindings.length,
  };

  const { grade, score, gradeColor } = calculateGrade(summary);

  // Detect OpenClaw version
  let openclawVersion = safeExec('openclaw --version');

  const result = {
    scan_date: new Date().toISOString(),
    openclaw_dir: openclawDir,
    openclaw_detected: !!openclawDir,
    openclaw_version: openclawVersion || null,
    grade,
    score,
    grade_color: gradeColor,
    summary,
    panels: {
      gateway,
      skills,
      config,
      identity,
      persistence,
      sessions,
    },
  };

  cachedScanResult = result;
  return result;
}

// -----------------------------------------------------------------------------
// Baseline Accept Handler
// -----------------------------------------------------------------------------

function acceptBaseline() {
  if (!openclawDir) {
    return { success: false, error: 'OpenClaw directory not detected' };
  }

  const workspaceDir = path.join(openclawDir, 'workspace');
  const baselinePath = path.join(openclawDir, BASELINE_FILE);
  const hashes = {};

  for (const file of IDENTITY_FILES) {
    const filePath = path.join(workspaceDir, file);
    const hash = hashFile(filePath);
    if (hash) {
      hashes[file] = hash;
    }
  }

  if (Object.keys(hashes).length === 0) {
    return { success: false, error: 'No identity files found to baseline' };
  }

  try {
    fs.writeFileSync(baselinePath, JSON.stringify(hashes, null, 2));
    return {
      success: true,
      message: `Baseline updated with ${Object.keys(hashes).length} file(s)`,
      files: Object.keys(hashes),
    };
  } catch (err) {
    return { success: false, error: `Failed to write baseline: ${err.message}` };
  }
}

// -----------------------------------------------------------------------------
// HTTP Server
// -----------------------------------------------------------------------------

function sendJSON(res, data, statusCode = 200) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-cache',
  });
  res.end(body);
}

function handleRequest(req, res) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Route: GET / — serve index.html
  if (pathname === '/' && req.method === 'GET') {
    const indexPath = path.join(__dirname, 'index.html');
    const html = safeReadFile(indexPath);
    if (html) {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
      });
      res.end(html);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('index.html not found. Place it alongside server.js.');
    }
    return;
  }

  // Route: GET /api/status — return cached scan results
  if (pathname === '/api/status' && req.method === 'GET') {
    if (!cachedScanResult) {
      cachedScanResult = runFullScan();
    }
    sendJSON(res, cachedScanResult);
    return;
  }

  // Route: GET /api/scan — trigger fresh scan
  if (pathname === '/api/scan' && req.method === 'GET') {
    const result = runFullScan();
    sendJSON(res, result);
    return;
  }

  // Route: GET /api/baseline/accept — update identity baseline
  if (pathname === '/api/baseline/accept' && req.method === 'GET') {
    const result = acceptBaseline();
    sendJSON(res, result, result.success ? 200 : 400);
    return;
  }

  // 404 for everything else
  sendJSON(res, { error: 'Not found', path: pathname }, 404);
}

// -----------------------------------------------------------------------------
// Startup
// -----------------------------------------------------------------------------

function main() {
  console.log('===========================================');
  console.log('  BulwarkAI — OpenClaw Security Dashboard');
  console.log('===========================================');

  // Detect OpenClaw directory
  openclawDir = detectOpenClawDir();
  if (openclawDir) {
    console.log(`[+] OpenClaw directory: ${openclawDir}`);
  } else {
    console.log('[!] OpenClaw directory not found');
    console.log('    Set OPENCLAW_DIR env var or install OpenClaw to ~/.openclaw/');
  }

  // Load IOC database
  const iocCount = loadIOCDatabase();
  console.log(`[+] IOC database: ${iocCount} malicious skill(s) loaded`);

  // Load credential patterns
  const credCount = loadCredentialPatterns();
  console.log(`[+] Credential patterns: ${credCount} pattern(s) loaded`);

  // Run initial scan
  console.log('[*] Running initial scan...');
  cachedScanResult = runFullScan();
  console.log(`[+] Initial scan complete — Grade: ${cachedScanResult.grade} (${cachedScanResult.score}/100)`);
  console.log(`    Findings: ${cachedScanResult.summary.critical} critical, ${cachedScanResult.summary.high} high, ${cachedScanResult.summary.medium} medium, ${cachedScanResult.summary.low} low`);

  // Start HTTP server
  const server = http.createServer(handleRequest);

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`[!] Port ${PORT} is already in use. Set SECURITY_DASHBOARD_PORT to use a different port.`);
      process.exit(1);
    }
    console.error(`[!] Server error: ${err.message}`);
  });

  server.listen(PORT, () => {
    console.log(`[+] Server listening on http://localhost:${PORT}`);
    console.log('');
    console.log('    Routes:');
    console.log('      GET /              — Dashboard UI');
    console.log('      GET /api/status    — Cached scan results');
    console.log('      GET /api/scan      — Fresh scan');
    console.log('      GET /api/baseline/accept — Accept identity baseline');
    console.log('');
  });
}

main();
