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
const TRUSTED_DOMAINS = [
  'github.com', 'gitlab.com', 'npmjs.com', 'docs.openclaw.ai', 'bulwarkai.io',
  'openweathermap.org', 'api.openai.com', 'api.anthropic.com', 'openrouter.ai',
  'api.together.xyz', 'api.groq.com', 'api.mistral.ai',
  'generativelanguage.googleapis.com', 'huggingface.co', 'pypi.org',
  'stackoverflow.com', 'developer.mozilla.org', 'wikipedia.org', 'example.com',
];

// URL extraction pattern
const URL_PATTERN = /https?:\/\/[^\s)"']+/g;

/**
 * Check if a URL belongs to a trusted domain using proper domain extraction.
 */
function isDomainTrusted(url) {
  try {
    const hostname = new URL(url).hostname;
    return TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  } catch {
    return false;
  }
}

// -----------------------------------------------------------------------------
// Global State
// -----------------------------------------------------------------------------

let cachedScanResult = null;
let openclawDir = null;
let iocDatabase = { skills: [], detection_patterns: [] };
let c2Database = { c2_ips: [], exfiltration: [], technique_signatures: {} };
let publisherDatabase = { publishers: [] };
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

/**
 * Compare two dot-separated version strings.
 * Returns -1 if a < b, 1 if a > b, 0 if equal.
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

/**
 * Check directory readability status.
 * Returns 'readable' if dir exists and has entries, 'empty' if exists but empty, 'missing' if not found.
 */
function checkDirectory(dirPath) {
  const stat = safeStat(dirPath);
  if (!stat || !stat.isDirectory()) return 'missing';
  const entries = safeReaddir(dirPath);
  return entries.length > 0 ? 'readable' : 'empty';
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
  iocDatabase.detection_patterns = data && data.detection_patterns ? data.detection_patterns : [];
  return iocDatabase.skills.length;
}

function loadC2Database() {
  const c2Path = path.join(__dirname, 'ioc', 'c2-domains.json');
  const data = safeParseJSON(safeReadFile(c2Path));
  if (data) {
    c2Database.c2_ips = data.c2_ips || [];
    c2Database.exfiltration = data.exfiltration || [];
    c2Database.technique_signatures = data.technique_signatures || {};
  }
  return c2Database.c2_ips.length;
}

function loadPublisherDatabase() {
  const pubPath = path.join(__dirname, 'ioc', 'malicious-publishers.json');
  const data = safeParseJSON(safeReadFile(pubPath));
  if (data && Array.isArray(data.publishers)) {
    publisherDatabase.publishers = data.publishers;
  }
  return publisherDatabase.publishers.length;
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
    checks.push({ status: 'clean', check: 'OpenClaw directory', detail: 'Not detected — set OPENCLAW_DIR or install OpenClaw' });
    return { status: 'green', title: 'Gateway Security', checks, findings };
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

  // Check authBypass
  if (gw.authBypass === true || config.authBypass === true) {
    findings.push({
      severity: 'CRITICAL',
      check: 'Auth bypass enabled',
      detail: 'authBypass is set to true — authentication can be skipped entirely',
      remediation: 'Set authBypass to false or remove the key from openclaw.json.',
    });
  }

  // Check TLS (skip for localhost-only binds)
  const isLoopback = ['127.0.0.1', 'loopback', 'localhost'].includes(gw.bind);
  if (gw.tls || gw.ssl || gw.https) {
    checks.push({
      status: 'clean',
      check: 'TLS configuration',
      detail: 'TLS/SSL is configured on the gateway',
    });
  } else if (isLoopback) {
    checks.push({
      status: 'clean',
      check: 'TLS configuration',
      detail: 'TLS not required (gateway is localhost-only)',
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
  const openclawVersion = safeExec('openclaw --version');
  if (openclawVersion) {
    checks.push({
      status: 'clean',
      check: 'OpenClaw version',
      detail: `Running version: ${openclawVersion}`,
    });
  }

  // Check version against CVE database
  const cvePath = path.join(__dirname, 'ioc', 'cves.json');
  const cveData = safeParseJSON(safeReadFile(cvePath));
  if (openclawVersion && cveData && cveData.minimum_safe_version) {
    const current = openclawVersion.trim().replace(/[^0-9.]/g, '');
    const safe = cveData.minimum_safe_version;
    if (current && compareVersions(current, safe) < 0) {
      findings.push({
        severity: 'HIGH',
        check: 'Outdated OpenClaw version',
        detail: `Running ${openclawVersion.trim()} — known vulnerabilities exist. Minimum safe version: ${safe}. ${cveData.total_cves} CVEs tracked.`,
        remediation: `Update OpenClaw to version ${safe} or later: openclaw update`,
      });
    }
  }

  // CVE-2026-28363: safeBins bypass via GNU long-option abbreviation
  if (openclawVersion) {
    const currentVer = openclawVersion.trim().replace(/[^0-9.]/g, '');
    const hasSafeBins = !!(config.safeBins || config.safe_bins || (config.exec && config.exec.safeBins));

    if (currentVer && compareVersions(currentVer, '2026.2.23') < 0 && hasSafeBins) {
      findings.push({
        severity: 'CRITICAL',
        check: 'CVE-2026-28363 — safeBins bypass',
        detail: 'safeBins bypass via GNU long-option abbreviation — safeBins configured but ineffective on pre-2026.2.23',
        remediation: 'Update to v2026.2.23+ to fix safeBins bypass (CVE-2026-28363)',
      });
    }

    // ClawJacked: WebSocket brute-force vulnerability
    if (currentVer && compareVersions(currentVer, '2026.2.25') < 0) {
      const clawjackedDetail = !gw.auth
        ? 'Gateway vulnerable to ClawJacked WebSocket brute-force (pre-2026.2.25) — auth is disabled, making this attack trivial'
        : 'Gateway vulnerable to ClawJacked WebSocket brute-force (pre-2026.2.25)';
      findings.push({
        severity: 'CRITICAL',
        check: 'ClawJacked — WebSocket brute-force',
        detail: clawjackedDetail,
        remediation: 'Update to v2026.2.25+ which adds WebSocket rate limiting',
      });
    }
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

  // Detection: Runtime network exposure — check actual listening port bind address
  const gwPort = (config && config.gateway && config.gateway.port) || 18789;
  try {
    let listenOutput = null;
    if (process.platform === 'darwin') {
      listenOutput = safeExec(`lsof -iTCP:${gwPort} -sTCP:LISTEN -nP 2>/dev/null || true`);
    } else {
      listenOutput = safeExec(`ss -tlnp 2>/dev/null | grep :${gwPort} || true`);
    }
    if (listenOutput && listenOutput.trim()) {
      if (/\*:|0\.0\.0\.0:/.test(listenOutput)) {
        findings.push({
          severity: 'CRITICAL',
          check: 'Gateway listening on all interfaces',
          detail: `Runtime check: gateway port ${gwPort} is bound to 0.0.0.0 (all interfaces) — exposed to the network`,
          remediation: `Rebind gateway to 127.0.0.1 in openclaw.json and restart.`,
        });
      } else if (/127\.0\.0\.1:|localhost:|\[::1\]:/.test(listenOutput)) {
        checks.push({
          status: 'clean',
          check: 'Runtime bind verification',
          detail: `Runtime bind verification confirmed — port ${gwPort} bound to loopback only`,
        });
      }
    }
  } catch {
    // Never block the scan on runtime check failure
  }

  return { status: panelStatus(findings), title: 'Gateway Security', checks, findings };
}

// -----------------------------------------------------------------------------
// Panel 2: Skill Supply Chain
// -----------------------------------------------------------------------------

// Find all skill directories across multiple locations:
// - ~/.openclaw/skills/ (primary)
// - ~/.openclaw/workspace/ (recursively find SKILL.md files, max depth 4)
// - ~/.openclaw/agents/*/skills/ (agent-specific)
// Returns an object with skills array and locations set.
function findAllSkillDirs(baseDir) {
  const skills = [];
  const locations = new Set();
  const seenDirs = new Set();

  // 1. Primary skills directory
  const skillsDir = path.join(baseDir, 'skills');
  if (checkDirectory(skillsDir) === 'readable') {
    locations.add('skills/');
    const entries = safeReaddir(skillsDir);
    for (const entry of entries) {
      const fullPath = path.join(skillsDir, entry);
      const stat = safeStat(fullPath);
      if (stat && stat.isDirectory() && !seenDirs.has(fullPath)) {
        seenDirs.add(fullPath);
        skills.push({ name: entry, dir: fullPath, source: 'skills/' });
      }
    }
  }

  // 2. Workspace — recursively find SKILL.md (max depth 4)
  const workspaceDir = path.join(baseDir, 'workspace');
  const findSkillMdRecursive = (dir, depth) => {
    if (depth > 4) return [];
    const results = [];
    const entries = safeReaddir(dir);
    for (const entry of entries) {
      const fullPath = path.join(dir, entry);
      const stat = safeStat(fullPath);
      if (!stat) continue;
      if (stat.isDirectory()) {
        results.push(...findSkillMdRecursive(fullPath, depth + 1));
      } else if (entry === 'SKILL.md') {
        results.push(fullPath);
      }
    }
    return results;
  };
  const workspaceSkillMds = findSkillMdRecursive(workspaceDir, 0);
  if (workspaceSkillMds.length > 0) {
    locations.add('workspace/');
    for (const mdPath of workspaceSkillMds) {
      const skillDir = path.dirname(mdPath);
      if (!seenDirs.has(skillDir)) {
        seenDirs.add(skillDir);
        skills.push({ name: path.basename(skillDir), dir: skillDir, source: 'workspace/' });
      }
    }
  }

  // 3. Agent-specific skills: agents/*/skills/
  const agentsDir = path.join(baseDir, 'agents');
  if (checkDirectory(agentsDir) === 'readable') {
    const agents = safeReaddir(agentsDir);
    for (const agent of agents) {
      const agentSkillsDir = path.join(agentsDir, agent, 'skills');
      if (checkDirectory(agentSkillsDir) === 'readable') {
        const locLabel = `agents/${agent}/skills/`;
        locations.add(locLabel);
        const entries = safeReaddir(agentSkillsDir);
        for (const entry of entries) {
          const fullPath = path.join(agentSkillsDir, entry);
          const stat = safeStat(fullPath);
          if (stat && stat.isDirectory() && !seenDirs.has(fullPath)) {
            seenDirs.add(fullPath);
            skills.push({ name: entry, dir: fullPath, source: locLabel });
          }
        }
      }
    }
  }

  return { skills, locations };
}

function scanSkills() {
  const checks = [];
  const findings = [];

  if (!openclawDir) {
    return { status: 'green', title: 'Skill Supply Chain', checks, findings };
  }

  // Multi-directory skill discovery
  const { skills: allSkillDirs, locations } = findAllSkillDirs(openclawDir);

  // Fallback: check if primary skills/ directory exists at all
  const skillsDir = path.join(openclawDir, 'skills');
  const skillsDirStatus = checkDirectory(skillsDir);
  if (skillsDirStatus === 'missing' && allSkillDirs.length === 0) {
    findings.push({
      severity: 'MEDIUM',
      check: 'Skills directory',
      detail: 'skills/ directory not found — cannot inventory installed skills',
      remediation: 'Create the skills/ directory or verify your OpenClaw installation.',
    });
    return { status: panelStatus(findings), title: 'Skill Supply Chain', checks, findings };
  }
  const skillEntries = safeReaddir(skillsDir);
  // Use multi-directory results as primary source, augment with legacy skillEntries
  const skillNames = [];
  const seenSkillDirs = new Set();

  // Add all skills found via findAllSkillDirs
  for (const skill of allSkillDirs) {
    if (!seenSkillDirs.has(skill.dir)) {
      seenSkillDirs.add(skill.dir);
      skillNames.push(skill);
    }
  }

  // Legacy fallback: also scan skillEntries from primary dir (in case findAllSkillDirs missed any)
  for (const entry of skillEntries) {
    const fullPath = path.join(skillsDir, entry);
    const stat = safeStat(fullPath);
    if (stat && stat.isDirectory() && !seenSkillDirs.has(fullPath)) {
      seenSkillDirs.add(fullPath);
      skillNames.push({ name: entry, dir: fullPath, source: 'skills/' });
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

  const locationCount = Math.max(locations.size, 1);
  checks.push({
    status: 'clean',
    check: 'Skill inventory',
    detail: `${skillNames.length} skill(s) found across ${locationCount} location(s)`,
  });

  // IOC name list (lowercase for comparison)
  const maliciousNames = iocDatabase.skills.map(s =>
    (typeof s === 'string' ? s : s.name || '').toLowerCase()
  );

  for (const skill of skillNames) {
    const skillName = skill.name;
    let iocMatch = false;

    // Cross-reference against IOC database
    if (maliciousNames.includes(skillName.toLowerCase())) {
      findings.push({
        severity: 'CRITICAL',
        check: 'Malicious skill detected',
        detail: `Skill "${skillName}" matches known malicious skill in IOC database`,
        remediation: `Remove the skill directory: rm -rf ${skill.dir}`,
        fixable: true, fixType: 'malicious_skill', fixPath: skill.dir,
      });
      iocMatch = true;
      continue;
    }

    // Pattern-based detection (catches unnamed variants)
    if (iocDatabase.detection_patterns) {
      for (const dp of iocDatabase.detection_patterns) {
        try {
          const re = new RegExp(dp.pattern, 'i');
          if (re.test(skillName) && !iocMatch) {
            findings.push({
              severity: 'HIGH',
              check: 'Suspicious skill name pattern',
              detail: `Skill "${skillName}" matches known malicious naming pattern: ${dp.pattern}${dp.note ? ' (' + dp.note + ')' : ''}`,
              remediation: `Review this skill carefully. Known malicious campaigns use similar names. Inspect SKILL.md and remove if not intentionally installed.`,
            });
            break;
          }
        } catch {}
      }
    }

    // Check SKILL.md content
    const skillMdPath = path.join(skill.dir, 'SKILL.md');
    const skillMd = safeReadFile(skillMdPath);
    if (skillMd) {
      // ClawHavoc ClickFix: prerequisites-style header AND pipe-to-shell patterns
      const hasPrereqHeader = /^#+\s*(prerequisites?|requirements?|before you begin)/im.test(skillMd);
      const hasSuspiciousExec = /(curl\s.*\|\s*(ba)?sh|wget\s.*\|\s*(ba)?sh|base64\s+-d\s*\||(ba)?sh\s+-c\s+['"]\s*\$\(curl|powershell\s+-enc|iwr\s.*-OutFile|\.\/[a-zA-Z0-9]+\s*&&\s*rm|password.*ZIP|Extract using pass:)/i.test(skillMd);
      if (hasPrereqHeader && hasSuspiciousExec) {
        findings.push({
          severity: 'CRITICAL',
          check: 'ClawHavoc ClickFix pattern',
          detail: `Skill "${skill.name}" SKILL.md contains a prerequisites header with download/exec commands — possible ClickFix social engineering`,
          remediation: `Review ${skillMdPath} carefully. Remove the skill if the commands are suspicious.`,
          fixable: true, fixType: 'suspicious_skill', fixPath: skill.dir,
        });
      }

      // External URLs not from trusted domains
      const urls = (skillMd.match(URL_PATTERN) || []).map(u => u.replace(/[`'")\]}>.,;:]+$/, ''));
      for (const url of urls) {
        if (!isDomainTrusted(url)) {
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

    // Check for executable files in skill directory and scan source files
    const skillFiles = safeReaddir(skill.dir);
    let executableFound = false;
    let c2IpFound = false;
    let exfilFound = false;
    let reverseShellFound = false;

    for (const file of skillFiles) {
      const ext = path.extname(file).toLowerCase();
      const filePath = path.join(skill.dir, file);
      const stat = safeStat(filePath);
      if (!stat || !stat.isFile()) continue;

      // Check if file is executable (skip .md/.txt/.json)
      if (!executableFound && !['.md', '.txt', '.json'].includes(ext)) {
        try {
          fs.accessSync(filePath, fs.constants.X_OK);
          findings.push({
            severity: 'HIGH',
            check: 'Executable in skill directory',
            detail: `Skill "${skill.name}" contains executable file: ${file}`,
            remediation: `Skill directories should contain only text files (SKILL.md, config). Executable files may indicate a compromised skill. Inspect with: file ${filePath} && cat ${filePath}. If you created this skill yourself, this is expected. If not, review contents carefully before trusting it.`,
          });
          executableFound = true;
        } catch {
          // Not executable — fine
        }
      }

      // Scan source files for C2 IPs, exfil domains, reverse shell patterns
      if (['.py', '.js', '.sh', '.ts', '.rb', '.pl', '.go', '.rs', '.bash', '.zsh'].includes(ext)) {
        const sourceContent = safeReadFile(filePath);
        if (!sourceContent) continue;

        // C2 IP detection
        if (!c2IpFound && c2Database.c2_ips.length > 0) {
          for (const entry of c2Database.c2_ips) {
            if (sourceContent.includes(entry.ip)) {
              findings.push({
                severity: 'CRITICAL',
                check: 'C2 IP address in skill code',
                detail: `Skill "${skill.name}" file ${file} contains known C2 IP: ${entry.ip} (${entry.usage})`,
                remediation: `Remove skill immediately: rm -rf ${skill.dir}`,
              });
              c2IpFound = true;
              break;
            }
          }
        }

        // Exfiltration domain detection
        if (!exfilFound && c2Database.exfiltration.length > 0) {
          for (const entry of c2Database.exfiltration) {
            if (sourceContent.includes(entry.domain)) {
              findings.push({
                severity: 'CRITICAL',
                check: 'Known exfiltration domain in skill code',
                detail: `Skill "${skill.name}" file ${file} contacts known exfil domain: ${entry.domain} (${entry.usage})`,
                remediation: `Remove skill immediately: rm -rf ${skill.dir}`,
              });
              exfilFound = true;
              break;
            }
          }
        }

        // Reverse shell pattern detection
        if (!reverseShellFound && c2Database.technique_signatures.reverse_shell) {
          for (const sig of c2Database.technique_signatures.reverse_shell) {
            try {
              if (new RegExp(sig, 'i').test(sourceContent)) {
                findings.push({
                  severity: 'CRITICAL',
                  check: 'Reverse shell pattern in skill code',
                  detail: `Skill "${skill.name}" file ${file} contains reverse shell pattern: ${sig}`,
                  remediation: `Remove skill immediately: rm -rf ${skill.dir}`,
                });
                reverseShellFound = true;
                break;
              }
            } catch {}
          }
        }
      }
    }

    // Publisher blacklist check — look for publisher metadata in SKILL.md
    if (skillMd && publisherDatabase.publishers.length > 0) {
      const pubMatch = skillMd.match(/^#+\s*(?:Publisher|Author|By)\s*\n+\s*(\S+)/im);
      if (pubMatch) {
        const pubName = pubMatch[1].toLowerCase();
        const maliciousPub = publisherDatabase.publishers.find(p => p.name.toLowerCase() === pubName);
        if (maliciousPub) {
          findings.push({
            severity: 'CRITICAL',
            check: 'Known malicious publisher',
            detail: `Skill "${skill.name}" is from known malicious publisher: ${maliciousPub.name} (campaign: ${maliciousPub.campaign}, ${maliciousPub.packages_published || 'unknown'} packages published)`,
            remediation: `Remove skill immediately: rm -rf ${skill.dir}`,
          });
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

  // Detection 9: Check ~/.openclaw/ directory permissions
  const openclawDirStat = safeStat(openclawDir);
  if (openclawDirStat) {
    const dirMode = openclawDirStat.mode & 0o777;
    if (dirMode & 0o077) {
      findings.push({
        severity: 'HIGH',
        check: 'OpenClaw directory permissions',
        detail: `~/.openclaw/ has permissions 0${dirMode.toString(8)} — group/world readable`,
        remediation: 'Run: chmod 700 ~/.openclaw/',
      });
    } else {
      checks.push({
        status: 'clean',
        check: 'OpenClaw directory permissions',
        detail: `~/.openclaw/ permissions are 0${dirMode.toString(8)} (owner-only)`,
      });
    }
  }

  // Detection 10: Check .env file permissions
  const envFilePath = path.join(openclawDir, '.env');
  const envFileStat = safeStat(envFilePath);
  if (envFileStat && envFileStat.isFile()) {
    const envMode = envFileStat.mode & 0o777;
    if (envMode & 0o077) {
      findings.push({
        severity: 'HIGH',
        check: '.env file permissions',
        detail: `.env has permissions 0${envMode.toString(8)} — group/world readable`,
        remediation: 'Run: chmod 600 ~/.openclaw/.env',
      });
    } else {
      checks.push({
        status: 'clean',
        check: '.env file permissions',
        detail: `.env permissions are 0${envMode.toString(8)} (owner-only)`,
      });
    }
  }

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

  // Scan openclaw.json content for API key patterns (skip env block at depth 0)
  const configContent = safeReadFile(configPath);
  if (configContent) {
    const parsedForKeyScan = safeParseJSON(configContent);
    if (parsedForKeyScan) {
      const scanObjForKeys = (obj, depth) => {
        if (!obj || typeof obj !== 'object') return;
        for (const [key, value] of Object.entries(obj)) {
          if (depth === 0 && key === 'env') continue;
          if (typeof value === 'string') {
            for (const pattern of API_KEY_PATTERNS) {
              if (pattern.test(value)) {
                findings.push({
                  severity: 'CRITICAL',
                  check: 'API key in configuration',
                  detail: `Found API key pattern in openclaw.json: ${value.substring(0, 8)}...`,
                  remediation: 'Move API keys to environment variables or the credentials/ directory. Never store them in openclaw.json.',
                });
                return; // one finding is enough
              }
            }
          } else if (typeof value === 'object' && value !== null) {
            scanObjForKeys(value, depth + 1);
          }
        }
      };
      scanObjForKeys(parsedForKeyScan, 0);
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

      // Check sandbox.mode specifically
      const sandboxMode = (typeof config.sandbox === 'object' && config.sandbox !== null)
        ? config.sandbox.mode
        : undefined;
      if (sandboxMode === 'off' || sandboxMode === false || (!sandboxMode && config.sandbox !== true && !(config.sandbox?.enabled === true))) {
        // Only flag if sandbox section exists but mode is off, or sandbox is not configured at all
        if (config.sandbox === undefined || sandboxMode === 'off' || sandboxMode === false) {
          findings.push({
            severity: 'HIGH',
            check: 'Sandbox mode off',
            detail: 'Sandbox mode is off — agent exec runs directly on host',
            remediation: 'Sandbox isolates tool execution in Docker containers, preventing skills from accessing your host system directly. Enable with sandbox.mode: \'all\' in openclaw.json (requires Docker). If Docker isn\'t available, configure a safeBins allowlist as the next best option.',
          });
        }
      }

      if (config.exec?.allow_all === true || config.exec?.unrestricted === true) {
        findings.push({
          severity: 'HIGH',
          check: 'Unrestricted execution',
          detail: 'Execution policy allows unrestricted command execution',
          remediation: 'Restrict exec permissions to specific allowed commands.',
        });
      }

      // Check for safeBins allowlist
      if (!config.safeBins && !config.safe_bins && !(config.exec && config.exec.safeBins)) {
        findings.push({
          severity: 'HIGH',
          check: 'No safeBins allowlist',
          detail: 'No safeBins command allowlist is configured — all binaries may be executable',
          remediation: 'Without a safeBins allowlist, any installed skill can execute any binary on your system. Add safeBins to openclaw.json with the commands your skills actually need (e.g., [\'ls\', \'cat\', \'grep\', \'node\', \'python\']). Start restrictive and add commands as needed.',
        });
      } else {
        const bins = config.safeBins || config.safe_bins || (config.exec && config.exec.safeBins);
        if (Array.isArray(bins)) {
          checks.push({
            status: 'clean',
            check: 'safeBins allowlist',
            detail: `safeBins allowlist configured with ${bins.length} command(s)`,
          });
        }
      }
    }

    if (findings.filter(f => f.check.includes('API key') || f.check.includes('Placeholder')).length === 0) {
      checks.push({
        status: 'clean',
        check: 'Secret scanning',
        detail: 'No API keys or placeholder values found in openclaw.json',
      });
    }

    // Detection 11: Debug logging check
    const parsedConfig = safeParseJSON(configContent);
    if (parsedConfig) {
      const logLevel = (parsedConfig.log_level || parsedConfig.logLevel ||
        (parsedConfig.gateway && (parsedConfig.gateway.log_level || parsedConfig.gateway.logLevel)) ||
        (parsedConfig.logging && parsedConfig.logging.level) || '').toLowerCase();
      if (logLevel === 'debug' || logLevel === 'trace') {
        findings.push({
          severity: 'MEDIUM',
          check: 'Debug logging enabled',
          detail: `Gateway log level is set to "${logLevel}" — may expose sensitive data in logs`,
          remediation: 'Set log level to "info" or "warn" in production environments.',
        });
      }
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

  // Check workspace/ directory existence
  const workspaceDirStatus = checkDirectory(workspaceDir);
  if (workspaceDirStatus === 'missing') {
    findings.push({
      severity: 'MEDIUM',
      check: 'Workspace directory',
      detail: 'workspace/ directory not found — cannot check identity file integrity',
      remediation: 'Create the workspace/ directory or verify your OpenClaw installation.',
    });
    return { status: panelStatus(findings), title: 'Identity Integrity', checks, findings };
  }

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

  // Detection 12: MEMORY.md and identity file credential scan
  const credScanFiles = ['MEMORY.md', ...IDENTITY_FILES];
  const scannedCredFiles = new Set();
  for (const file of credScanFiles) {
    if (scannedCredFiles.has(file)) continue;
    scannedCredFiles.add(file);
    const filePath = path.join(workspaceDir, file);
    const content = safeReadFile(filePath);
    if (!content) continue;
    for (const pattern of API_KEY_PATTERNS) {
      const re = (pattern instanceof RegExp) ? pattern : new RegExp(pattern.regex || pattern, 'i');
      if (re.test(content)) {
        findings.push({
          severity: 'CRITICAL',
          check: 'Credential in identity file',
          detail: `${file} contains an API key pattern — credentials must not be stored in identity files`,
          remediation: `Remove the credential from ${filePath} immediately and rotate the exposed key.`,
        });
        break; // One finding per file
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
    if (plist === 'io.bulwarkai.dashboard.plist') continue;
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

  // Check hooks/ directories (both primary and workspace)
  const hooksDirs = [
    path.join(openclawDir, 'hooks'),
    path.join(openclawDir, 'workspace', 'hooks'),
  ];

  const HOOK_NETWORK_PATTERNS = /\b(curl|wget|fetch|https?:\/\/|webhook\.site|ngrok)\b/i;
  let totalHookCount = 0;

  for (const hooksDir of hooksDirs) {
    const hookEntries = safeReaddir(hooksDir);
    const hookFiles = [];

    // Find HOOK.md and *.hook.md files at top level and in subdirectories
    for (const entry of hookEntries) {
      const entryPath = path.join(hooksDir, entry);
      const stat = safeStat(entryPath);
      if (!stat) continue;

      if (stat.isDirectory()) {
        // Check subdirectory for HOOK.md or *.hook.md
        const subEntries = safeReaddir(entryPath);
        for (const sub of subEntries) {
          if (sub === 'HOOK.md' || sub.endsWith('.hook.md')) {
            hookFiles.push(path.join(entryPath, sub));
          }
        }
      } else if (entry === 'HOOK.md' || entry.endsWith('.hook.md')) {
        hookFiles.push(entryPath);
      }
    }

    totalHookCount += hookFiles.length;

    if (hookFiles.length > 0) {
      findings.push({
        severity: 'MEDIUM',
        check: 'Custom hooks detected',
        detail: `Found ${hookFiles.length} hook(s) in ${hooksDir.replace(HOME, '~')} — hooks execute on every Gateway event`,
        remediation: 'Review all hook definitions to ensure they perform expected actions.',
      });

      // Scan hook content for suspicious network patterns
      for (const hookFile of hookFiles) {
        const hookContent = safeReadFile(hookFile);
        if (hookContent && HOOK_NETWORK_PATTERNS.test(hookContent)) {
          findings.push({
            severity: 'HIGH',
            check: 'Hook with network access',
            detail: `Hook ${path.basename(hookFile)} in ${path.dirname(hookFile).replace(HOME, '~')} contains network access patterns (curl/wget/fetch/http)`,
            remediation: `Review ${hookFile.replace(HOME, '~')} — hooks with network access can exfiltrate data on every Gateway event.`,
          });
          break; // One network finding per hooks directory
        }
      }
    }
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
  const sessionsDirStatus = checkDirectory(sessionsDir);
  if (sessionsDirStatus === 'missing') {
    findings.push({
      severity: 'LOW',
      check: 'Sessions directory',
      detail: 'sessions/ directory not found — session analysis unavailable',
      remediation: 'Sessions directory will be created when OpenClaw records its first session.',
    });
    return { status: panelStatus(findings), title: 'Session Analysis', checks, findings };
  }
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
// Panel 7: MCP Security
// -----------------------------------------------------------------------------

function scanMCP() {
  const checks = [];
  const findings = [];

  if (!openclawDir) {
    return { status: 'green', title: 'MCP Security', checks, findings };
  }

  // Try mcp.json then mcp.json5
  let mcpContent = null;
  let mcpPath = path.join(openclawDir, 'mcp.json');
  mcpContent = safeReadFile(mcpPath);
  if (!mcpContent) {
    mcpPath = path.join(openclawDir, 'mcp.json5');
    mcpContent = safeReadFile(mcpPath);
  }

  if (!mcpContent) {
    checks.push({
      status: 'clean',
      check: 'MCP configuration',
      detail: 'No mcp.json or mcp.json5 found — no MCP servers configured',
    });
    return { status: 'green', title: 'MCP Security', checks, findings };
  }

  // Parse JSON (json5 files may fail with strict parser — best effort)
  const mcpConfig = safeParseJSON(mcpContent);
  if (!mcpConfig) {
    findings.push({
      severity: 'MEDIUM',
      check: 'MCP configuration parse error',
      detail: `${path.basename(mcpPath)} exists but could not be parsed as valid JSON`,
      remediation: 'Fix the JSON syntax in your MCP configuration file.',
    });
    return { status: panelStatus(findings), title: 'MCP Security', checks, findings };
  }

  // Extract servers from common config shapes
  const servers = mcpConfig.servers || mcpConfig.mcpServers || {};
  const serverNames = Object.keys(servers);
  const serverCount = serverNames.length;

  if (serverCount === 0) {
    checks.push({
      status: 'clean',
      check: 'MCP servers',
      detail: 'MCP config found but no servers configured',
    });
    return { status: 'green', title: 'MCP Security', checks, findings };
  }

  checks.push({
    status: 'clean',
    check: 'MCP servers',
    detail: `${serverCount} MCP server(s) configured`,
  });

  // Check for unpinned versions
  for (const [name, serverConfig] of Object.entries(servers)) {
    if (!serverConfig || typeof serverConfig !== 'object') continue;
    const version = serverConfig.version || serverConfig.tag || '';
    const command = serverConfig.command || '';

    // Check explicit version/tag fields
    if (version === 'latest' || version === '*') {
      findings.push({
        severity: 'HIGH',
        check: 'Unpinned MCP server version',
        detail: `MCP server "${name}" uses unpinned version: "${version}"`,
        remediation: `Pin the version of MCP server "${name}" to a specific release tag.`,
      });
    } else if (!version && !serverConfig.version && !serverConfig.tag) {
      // No version/tag specified at all — check if command implies versioning
      const hasVersionInCmd = /[:@][0-9]+\.[0-9]+/.test(command) || /[:@]v[0-9]+/.test(command);
      if (!hasVersionInCmd && command) {
        findings.push({
          severity: 'HIGH',
          check: 'Unpinned MCP server version',
          detail: `MCP server "${name}" has no version or tag pinned`,
          remediation: `Add a version or tag field to MCP server "${name}" to pin it to a specific release.`,
        });
      }
    }
  }

  // Informational: large number of servers
  if (serverCount > 10) {
    findings.push({
      severity: 'LOW',
      check: 'Large MCP server count',
      detail: `${serverCount} MCP servers configured — large attack surface`,
      remediation: 'Review configured MCP servers and remove any that are not actively needed.',
    });
  }

  return { status: panelStatus(findings), title: 'MCP Security', checks, findings };
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

/**
 * Detection 13: Determine credential protection level (L0-L4).
 * L0 = plaintext keys in config, L1 = env var refs ($VAR), L2 = env block in config,
 * L3 = credentials/ directory, L4 = external vault / no keys detected.
 */
function detectCredentialLevel() {
  if (!openclawDir) return { level: 'L4', label: 'No config' };
  const configPath = path.join(openclawDir, 'openclaw.json');
  const configContent = safeReadFile(configPath);
  if (!configContent) return { level: 'L4', label: 'No config' };
  const config = safeParseJSON(configContent);
  if (!config) return { level: 'L4', label: 'No config' };

  // Check for plaintext API keys (excluding env block)
  let hasPlaintextKeys = false;
  const checkPlaintext = (obj, depth) => {
    if (!obj || typeof obj !== 'object') return;
    for (const [key, value] of Object.entries(obj)) {
      if (depth === 0 && key === 'env') continue;
      if (typeof value === 'string') {
        for (const pattern of API_KEY_PATTERNS) {
          if (pattern.test(value)) { hasPlaintextKeys = true; return; }
        }
      } else if (typeof value === 'object' && value !== null) {
        checkPlaintext(value, depth + 1);
        if (hasPlaintextKeys) return;
      }
    }
  };
  checkPlaintext(config, 0);
  if (hasPlaintextKeys) return { level: 'L0', label: 'Plaintext keys in config' };

  // Check for credentials/ directory with files
  const credsDir = path.join(openclawDir, 'credentials');
  const credsDirStatus = checkDirectory(credsDir);
  if (credsDirStatus === 'readable') return { level: 'L3', label: 'Credentials directory' };

  // Check for env block in config
  if (config.env && typeof config.env === 'object' && Object.keys(config.env).length > 0) {
    return { level: 'L2', label: 'Config env block' };
  }

  // Check for $VAR references in config values
  let hasEnvRefs = false;
  const checkEnvRefs = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    for (const value of Object.values(obj)) {
      if (typeof value === 'string' && /^\$[A-Z_]+/.test(value)) { hasEnvRefs = true; return; }
      if (typeof value === 'object' && value !== null) {
        checkEnvRefs(value);
        if (hasEnvRefs) return;
      }
    }
  };
  checkEnvRefs(config);
  if (hasEnvRefs) return { level: 'L1', label: 'Env var references' };

  return { level: 'L4', label: 'No keys detected' };
}

function runFullScan() {
  const gateway = scanGateway();
  const skills = scanSkills();
  const config = scanConfig();
  const identity = scanIdentity();
  const persistence = scanPersistence();
  const sessions = scanSessions();
  const mcp = scanMCP();

  const allFindings = [
    ...gateway.findings,
    ...skills.findings,
    ...config.findings,
    ...identity.findings,
    ...persistence.findings,
    ...sessions.findings,
    ...mcp.findings,
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

  // Detection 13: Credential protection level
  const credLevel = detectCredentialLevel();

  const pkg = safeParseJSON(safeReadFile(path.join(__dirname, 'package.json'))) || {};

  const result = {
    version: pkg.version || '1.4.1',
    scan_date: new Date().toISOString(),
    openclaw_dir: openclawDir,
    openclaw_detected: !!openclawDir,
    openclaw_version: openclawVersion || null,
    credential_level: credLevel,
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
      mcp,
    },
  };

  cachedScanResult = result;

  // Layer 1: Write status file to ~/.openclaw/ for integration with other dashboards
  writeSecurityStatus(result);

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
// Integration: Filesystem Status File
// -----------------------------------------------------------------------------

function writeSecurityStatus(result) {
  if (!openclawDir) return;
  const statusFile = path.join(openclawDir, '.security-status.json');
  const pkg = safeParseJSON(safeReadFile(path.join(__dirname, 'package.json'))) || {};
  const iocVer = safeReadFile(path.join(__dirname, 'ioc', 'VERSION'));
  const status = {
    tool: 'openclaw-security-dashboard',
    tool_version: pkg.version || '0.1.0',
    ioc_version: iocVer ? iocVer.split('\n')[0].trim() : 'unknown',
    scan_date: result.scan_date,
    grade: result.grade,
    score: result.score,
    summary: result.summary,
    panels: {},
    dashboard_url: `http://localhost:${PORT}`,
    more_info: 'https://bulwarkai.io',
  };
  for (const [key, panel] of Object.entries(result.panels)) {
    status.panels[key] = {
      status: panel.status,
      label: panel.title,
      findings: (panel.findings || []).length,
    };
  }
  try {
    fs.writeFileSync(statusFile, JSON.stringify(status, null, 2));
  } catch { /* non-critical */ }
}

// -----------------------------------------------------------------------------
// Integration: Embeddable Widget
// -----------------------------------------------------------------------------

function renderEmbed(data, theme) {
  const dark = theme !== 'light';
  const bg = dark ? '#0E1217' : '#f8f9fa';
  const border = dark ? 'rgba(255,159,46,0.3)' : '#dee2e6';
  const text = dark ? '#F0EDE8' : '#212529';
  const muted = dark ? '#9CA3AF' : '#6c757d';
  const gc = data.grade_color || '#9CA3AF';
  const dots = Object.values(data.panels || {}).map(p => {
    const c = p.status === 'red' ? '#ef4444' : p.status === 'amber' ? '#f59e0b' : '#22c55e';
    return `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${c}"></span>`;
  }).join(' ');
  const s = data.summary || {};
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:${bg};color:${text};padding:12px 16px;border:1px solid ${border};border-radius:8px}
a{color:#FF9F2E;text-decoration:none}a:hover{text-decoration:underline}
.grade{font-size:1.5rem;font-weight:800;color:${gc};font-family:monospace}
.dots{margin:6px 0;display:flex;align-items:center;gap:5px}
.meta{font-size:11px;color:${muted};font-family:monospace}
.cta{font-size:10px;color:${muted};margin-top:6px}
</style></head><body>
<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
<span class="grade">${data.grade || '?'}</span>
<span style="font-size:13px;font-weight:600">Security</span>
<span class="meta">${data.score ?? '?'}/100</span>
</div>
<div class="dots">${dots} <span class="meta">${s.total || 0} finding${s.total !== 1 ? 's' : ''}</span></div>
<div class="meta">${s.critical || 0} critical · ${s.high || 0} high · ${s.medium || 0} med · ${s.low || 0} low</div>
<div class="cta">Powered by <a href="https://bulwarkai.io" target="_blank">BulwarkAI</a></div>
<script>setInterval(()=>fetch('/api/status').then(r=>r.json()).then(d=>{location.reload()}).catch(()=>{}),60000)</script>
</body></html>`;
}

// -----------------------------------------------------------------------------
// HTTP Server
// -----------------------------------------------------------------------------

function sendJSON(res, data, statusCode = 200) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

  // Route: GET /embed — embeddable compact widget
  if (pathname === '/embed' && req.method === 'GET') {
    if (!cachedScanResult) cachedScanResult = runFullScan();
    const theme = url.searchParams.get('theme') || 'dark';
    const html = renderEmbed(cachedScanResult, theme);
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache',
    });
    res.end(html);
    return;
  }

  // Route: POST /api/fix — apply auto-fixes
  if (pathname === '/api/fix' && req.method === 'POST') {
    if (!openclawDir) {
      sendJSON(res, { error: 'No OpenClaw installation detected' }, 400);
      return;
    }
    const beforeResult = cachedScanResult || runFullScan();
    const fixable = identifyFixableFindings(beforeResult);
    if (fixable.length === 0) {
      sendJSON(res, {
        before: { grade: beforeResult.grade, score: beforeResult.score, summary: beforeResult.summary },
        after: { grade: beforeResult.grade, score: beforeResult.score, summary: beforeResult.summary },
        fixes_applied: [],
        fixes_failed: [],
        env_warnings: [],
        remaining: collectRemainingFindings(beforeResult, []),
        backup_path: null,
      });
      return;
    }
    const beforeGrade = beforeResult.grade;
    const beforeScore = beforeResult.score;
    const beforeSummary = { ...beforeResult.summary };
    let fixResult;
    try {
      fixResult = applyFixes(beforeResult);
    } catch (err) {
      sendJSON(res, { error: `Fix failed: ${err.message}` }, 500);
      return;
    }
    cachedScanResult = runFullScan();
    const after = cachedScanResult;
    const remaining = collectRemainingFindings(after, fixResult.fixes_applied);
    sendJSON(res, {
      before: { grade: beforeGrade, score: beforeScore, summary: beforeSummary },
      after: { grade: after.grade, score: after.score, summary: after.summary },
      fixes_applied: fixResult.fixes_applied,
      fixes_failed: fixResult.fixes_failed,
      env_warnings: fixResult.env_warnings,
      remaining,
      backup_path: fixResult.backup_path,
    });
    return;
  }

  // Route: GET /api/fixable — check what's auto-fixable (no changes)
  if (pathname === '/api/fixable' && req.method === 'GET') {
    if (!cachedScanResult) cachedScanResult = runFullScan();
    const fixable = identifyFixableFindings(cachedScanResult);
    sendJSON(res, { count: fixable.length, fixes: fixable.map(f => ({ type: f.type, detail: f.finding.detail })) });
    return;
  }

  // Route: GET /api/baseline/accept — update identity baseline
  if (pathname === '/api/baseline/accept' && req.method === 'GET') {
    const result = acceptBaseline();
    sendJSON(res, result, result.success ? 200 : 400);
    return;
  }

  // Route: GET /api/watch — return watcher state
  if (pathname === '/api/watch' && req.method === 'GET') {
    try {
      const { getWatcherState } = require('./lib/watcher');
      sendJSON(res, getWatcherState());
    } catch {
      sendJSON(res, { active: false, intervalMinutes: 0, nextScanAt: null, lastGrade: null });
    }
    return;
  }

  // 404 for everything else
  sendJSON(res, { error: 'Not found', path: pathname }, 404);
}

// -----------------------------------------------------------------------------
// CLI Flag Parsing
// -----------------------------------------------------------------------------

const args = process.argv.slice(2);
const FLAG_JSON = args.includes('--json');
const FLAG_FIX = args.includes('--fix');
const FLAG_NO_BROWSER = args.includes('--no-browser');
const FLAG_SERVICE = args.includes('--service');
const FLAG_WATCH = args.includes('--watch');
const WATCH_INTERVAL = (() => {
  const idx = args.indexOf('--watch-interval');
  return idx !== -1 && args[idx + 1] ? parseInt(args[idx + 1], 10) : 30;
})();

/**
 * Auto-open a URL in the default browser (macOS/Linux/Windows).
 */
function openBrowser(url) {
  const platform = process.platform;
  let cmd;
  if (platform === 'darwin') cmd = 'open';
  else if (platform === 'win32') cmd = 'start';
  else cmd = 'xdg-open';
  try {
    execSync(`${cmd} ${url}`, { stdio: 'ignore' });
  } catch {
    // Silently fail — headless environments, SSH, etc.
  }
}

// -----------------------------------------------------------------------------
// Auto-Fix Engine (--fix flag)
// -----------------------------------------------------------------------------

/**
 * Map of API key prefixes to environment variable names.
 */
const API_KEY_ENV_MAP = [
  { pattern: /^sk-ant-/, envVar: '$ANTHROPIC_API_KEY', label: 'Anthropic' },
  { pattern: /^sk-proj-/, envVar: '$OPENAI_API_KEY', label: 'OpenAI' },
  { pattern: /^sk-[a-zA-Z0-9]/, envVar: '$OPENAI_API_KEY', label: 'OpenAI' },
  { pattern: /^ghp_/, envVar: '$GITHUB_TOKEN', label: 'GitHub' },
  { pattern: /^gho_/, envVar: '$GITHUB_TOKEN', label: 'GitHub' },
  { pattern: /^xoxb-/, envVar: '$SLACK_BOT_TOKEN', label: 'Slack' },
  { pattern: /^AKIA/, envVar: '$AWS_ACCESS_KEY_ID', label: 'AWS' },
];

/**
 * Default safeBins allowlist for mechanical fix.
 */
const DEFAULT_SAFE_BINS = ['ls', 'cat', 'grep', 'head', 'tail', 'wc', 'find', 'which', 'echo', 'date', 'pwd'];

/**
 * Build a summary line like "4 critical · 3 high · 2 medium"
 */
function formatSummaryLine(summary) {
  const parts = [];
  if (summary.critical > 0) parts.push(`${summary.critical} critical`);
  if (summary.high > 0) parts.push(`${summary.high} high`);
  if (summary.medium > 0) parts.push(`${summary.medium} medium`);
  if (summary.low > 0) parts.push(`${summary.low} low`);
  return parts.length > 0 ? parts.join(' \u00b7 ') : 'No issues found';
}

/**
 * Determine which fixes are applicable based on scan findings.
 * Returns an array of fix descriptors.
 */
function identifyFixableFindings(scanResult) {
  const fixable = [];
  const allFindings = [];
  for (const panel of Object.values(scanResult.panels)) {
    for (const f of (panel.findings || [])) {
      allFindings.push(f);
    }
  }

  for (const f of allFindings) {
    if (f.check === 'Gateway bind address' && f.severity === 'CRITICAL') {
      fixable.push({ type: 'gateway_bind', finding: f });
    } else if (f.check === 'Config file permissions') {
      fixable.push({ type: 'config_permissions', finding: f });
    } else if (f.check === 'Auth bypass enabled') {
      fixable.push({ type: 'auth_bypass', finding: f });
    } else if (f.check === 'No safeBins allowlist') {
      fixable.push({ type: 'safe_bins', finding: f });
    } else if (f.check === 'API key in configuration') {
      fixable.push({ type: 'api_key', finding: f });
    } else if (f.check === 'Malicious skill detected' && f.fixPath) {
      fixable.push({ type: 'malicious_skill', finding: f, path: f.fixPath });
    } else if (f.check === 'ClawHavoc ClickFix pattern' && f.fixPath) {
      fixable.push({ type: 'suspicious_skill', finding: f, path: f.fixPath });
    }
  }

  return fixable;
}

/**
 * Create a timestamped backup of files that will be modified.
 * Returns the backup directory path, or throws on failure.
 */
function createBackup(openclawDir) {
  const now = new Date();
  const ts = now.getFullYear().toString() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0') + '-' +
    String(now.getHours()).padStart(2, '0') +
    String(now.getMinutes()).padStart(2, '0') +
    String(now.getSeconds()).padStart(2, '0');
  const backupDir = path.join(openclawDir, `.bulwarkai-backup-${ts}`);

  try {
    fs.mkdirSync(backupDir, { recursive: true });
  } catch (err) {
    throw new Error(`Failed to create backup directory ${backupDir}: ${err.message}`);
  }

  // Backup openclaw.json
  const openclawJson = path.join(openclawDir, 'openclaw.json');
  if (safeStat(openclawJson)) {
    try {
      fs.copyFileSync(openclawJson, path.join(backupDir, 'openclaw.json'));
    } catch (err) {
      throw new Error(`Failed to backup openclaw.json: ${err.message}`);
    }
  }

  // Backup config.json if it exists
  const configJson = path.join(openclawDir, 'config.json');
  if (safeStat(configJson)) {
    try {
      fs.copyFileSync(configJson, path.join(backupDir, 'config.json'));
    } catch { /* non-critical */ }
  }

  return backupDir;
}

/**
 * Apply mechanical fixes based on identified fixable findings.
 * Returns { fixes_applied: [...], fixes_failed: [...], backup_path, env_warnings: [...] }
 */
function applyFixes(scanResult) {
  const fixable = identifyFixableFindings(scanResult);
  if (fixable.length === 0) {
    return { fixes_applied: [], fixes_failed: [], backup_path: null, env_warnings: [] };
  }

  // Create backup (abort entirely if this fails)
  let backupPath;
  try {
    backupPath = createBackup(openclawDir);
  } catch (err) {
    console.error(`\n[!] ${err.message}`);
    console.error('[!] Aborting --fix: cannot proceed without a backup.\n');
    process.exit(1);
  }

  const fixesApplied = [];
  const fixesFailed = [];
  const envWarnings = [];

  // Read openclaw.json for modifications
  const configPath = path.join(openclawDir, 'openclaw.json');
  let config = safeParseJSON(safeReadFile(configPath));
  let configModified = false;

  for (const fix of fixable) {
    try {
      switch (fix.type) {
        case 'gateway_bind': {
          if (config && config.gateway) {
            config.gateway.bind = '127.0.0.1';
            configModified = true;
            fixesApplied.push('Gateway rebound to 127.0.0.1');
          } else {
            fixesFailed.push('Gateway bind: no gateway section in config');
          }
          break;
        }

        case 'config_permissions': {
          try {
            fs.chmodSync(configPath, 0o600);
            fixesApplied.push('File permissions set to 600');
          } catch (err) {
            fixesFailed.push(`File permissions: ${err.message}`);
          }
          break;
        }

        case 'auth_bypass': {
          if (config) {
            if (config.gateway && config.gateway.authBypass !== undefined) {
              delete config.gateway.authBypass;
              configModified = true;
            }
            if (config.authBypass !== undefined) {
              delete config.authBypass;
              configModified = true;
            }
            fixesApplied.push('authBypass disabled');
          } else {
            fixesFailed.push('authBypass: could not parse config');
          }
          break;
        }

        case 'safe_bins': {
          if (config) {
            config.safeBins = DEFAULT_SAFE_BINS;
            configModified = true;
            fixesApplied.push(`safeBins allowlist added (${DEFAULT_SAFE_BINS.length} commands)`);
            envWarnings.push('safeBins allowlist applied — skills requiring unlisted binaries (e.g. python, node, git) may break. Review and extend the list as needed.');
          } else {
            fixesFailed.push('safeBins: could not parse config');
          }
          break;
        }

        case 'api_key': {
          if (config) {
            let modified = false;
            // Ensure top-level env block exists
            if (!config.env || typeof config.env !== 'object') {
              config.env = {};
            }
            // Walk all string values in the config and move raw keys into env block
            const replaceKeys = (obj, depth) => {
              if (!obj || typeof obj !== 'object') return;
              for (const [key, value] of Object.entries(obj)) {
                // Skip the env block itself at depth 0
                if (depth === 0 && key === 'env') continue;
                if (typeof value === 'string') {
                  for (const mapping of API_KEY_ENV_MAP) {
                    if (mapping.pattern.test(value)) {
                      const truncated = value.substring(0, 8) + '...';
                      const envName = mapping.envVar.replace(/^\$/, '');
                      config.env[envName] = value;
                      obj[key] = mapping.envVar;
                      envWarnings.push(`Set env var ${mapping.envVar} to your ${mapping.label} key (was ${truncated})`);
                      modified = true;
                      break;
                    }
                  }
                } else if (typeof value === 'object' && value !== null) {
                  replaceKeys(value, depth + 1);
                }
              }
            };
            replaceKeys(config, 0);
            if (modified) {
              configModified = true;
              fixesApplied.push('API keys moved to config.env block with $VAR references');
            }
          } else {
            fixesFailed.push('API keys: could not parse config');
          }
          break;
        }

        case 'malicious_skill':
        case 'suspicious_skill': {
          const skillPath = fix.path;
          if (skillPath && fs.existsSync(skillPath)) {
            const backupDir = path.join(openclawDir, '.dashboard-backups', `skill-${path.basename(skillPath)}-${Date.now()}`);
            fs.cpSync(skillPath, backupDir, { recursive: true });
            fs.rmSync(skillPath, { recursive: true, force: true });
            fixesApplied.push(`Removed ${fix.type === 'malicious_skill' ? 'malicious' : 'suspicious'} skill: ${path.basename(skillPath)} (backed up to ${backupDir})`);
          }
          break;
        }
      }
    } catch (err) {
      fixesFailed.push(`${fix.type}: ${err.message}`);
    }
  }

  // Write modified config back
  if (configModified && config) {
    try {
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
    } catch (err) {
      // If we can't write back, report all config fixes as failed
      const configFixes = fixesApplied.filter(f =>
        f.includes('Gateway') || f.includes('authBypass') || f.includes('safeBins') || f.includes('API keys')
      );
      for (const cf of configFixes) {
        const idx = fixesApplied.indexOf(cf);
        if (idx !== -1) fixesApplied.splice(idx, 1);
        fixesFailed.push(`${cf}: failed to write config — ${err.message}`);
      }
    }
  }

  return { fixes_applied: fixesApplied, fixes_failed: fixesFailed, backup_path: backupPath, env_warnings: envWarnings };
}

/**
 * Collect remaining (non-fixable) findings from a scan result.
 */
function collectRemainingFindings(scanResult, fixesApplied) {
  const remaining = [];
  const allFindings = [];
  for (const panel of Object.values(scanResult.panels)) {
    for (const f of (panel.findings || [])) {
      allFindings.push(f);
    }
  }
  // Filter to only findings that still exist after re-scan
  for (const f of allFindings) {
    remaining.push({
      severity: f.severity,
      check: f.check,
      detail: f.detail,
      remediation: f.remediation,
    });
  }
  return remaining;
}

// -----------------------------------------------------------------------------
// Startup
// -----------------------------------------------------------------------------

function loadAllDatabases() {
  openclawDir = detectOpenClawDir();
  loadIOCDatabase();
  loadC2Database();
  loadPublisherDatabase();
  loadCredentialPatterns();
}

function main() {
  const pkg = safeParseJSON(safeReadFile(path.join(__dirname, 'package.json'))) || {};
  const version = pkg.version || '1.0.0';

  // Print version
  console.log(`OpenClaw Security Dashboard v${version}\n`);

  // Load databases
  loadAllDatabases();

  // Run initial scan
  cachedScanResult = runFullScan();
  const r = cachedScanResult;
  const s = r.summary;

  // --fix mode: apply mechanical fixes, re-scan, show comparison
  if (FLAG_FIX) {
    if (!openclawDir) {
      console.error('\n[!] --fix requires an OpenClaw installation. Set OPENCLAW_DIR or install to ~/.openclaw/\n');
      process.exit(1);
    }

    const fixable = identifyFixableFindings(r);
    if (fixable.length === 0) {
      if (FLAG_JSON) {
        const output = {
          before: { grade: r.grade, score: r.score, summary: { ...r.summary } },
          after: { grade: r.grade, score: r.score, summary: { ...r.summary } },
          fixes_applied: [],
          fixes_failed: [],
          env_warnings: [],
          remaining: collectRemainingFindings(r, []),
          backup_path: null,
          scan: r,
        };
        process.stdout.write(JSON.stringify(output, null, 2) + '\n');
        if (r.grade.startsWith('A') || r.grade.startsWith('B')) process.exit(0);
        if (r.grade === 'F') process.exit(2);
        process.exit(1);
      }
      console.log('\n[i] No auto-fixable issues found.\n');
      // Fall through to start server
    } else {
      // Store before state
      const beforeGrade = r.grade;
      const beforeScore = r.score;
      const beforeSummary = { ...r.summary };

      // Apply fixes
      const fixResult = applyFixes(r);
      if (!FLAG_JSON) {
        console.log(`\n[\u2713] Backup created: ${fixResult.backup_path}/`);
        for (const applied of fixResult.fixes_applied) {
          console.log(`[\u2713] ${applied}`);
        }
        for (const failed of fixResult.fixes_failed) {
          console.error(`[!] Fix failed: ${failed}`);
        }
        if (fixResult.env_warnings.length > 0) {
          console.log('');
          console.log('[!] Environment variables needed:');
          for (const w of fixResult.env_warnings) {
            console.log(`    \u26a0 ${w}`);
          }
        }
      }

      // Re-scan after fixes
      cachedScanResult = runFullScan();
      const after = cachedScanResult;
      const afterSummary = after.summary;

      // Collect remaining findings from the re-scan
      const remaining = collectRemainingFindings(after, fixResult.fixes_applied);

      // --fix --json mode
      if (FLAG_JSON) {
        const output = {
          before: {
            grade: beforeGrade,
            score: beforeScore,
            summary: beforeSummary,
          },
          after: {
            grade: after.grade,
            score: after.score,
            summary: afterSummary,
          },
          fixes_applied: fixResult.fixes_applied,
          fixes_failed: fixResult.fixes_failed,
          env_warnings: fixResult.env_warnings,
          remaining,
          backup_path: fixResult.backup_path,
          scan: after,
        };
        process.stdout.write(JSON.stringify(output, null, 2) + '\n');
        if (after.grade.startsWith('A') || after.grade.startsWith('B')) process.exit(0);
        if (after.grade === 'F') process.exit(2);
        process.exit(1);
      }

      // --fix (no json): print before/after comparison
      console.log('');
      console.log(`Before: Grade ${beforeGrade} (score ${beforeScore}/100) \u2014 ${formatSummaryLine(beforeSummary)}`);
      console.log(`After:  Grade ${after.grade} (score ${after.score}/100) \u2014 ${formatSummaryLine(afterSummary)}`);
      console.log('');
      console.log('Fixed:');
      for (const f of fixResult.fixes_applied) {
        console.log(`  \u2713 ${f}`);
      }
      if (fixResult.fixes_failed.length > 0) {
        console.log('');
        console.log('Failed:');
        for (const f of fixResult.fixes_failed) {
          console.log(`  \u2717 ${f}`);
        }
      }

      if (remaining.length > 0) {
        console.log('');
        console.log('Remaining (requires manual review):');
        for (const rem of remaining) {
          console.log(`  \u26a0 ${rem.detail}`);
        }
      }

      console.log('');
      console.log(`These fixes are reversible. Backup at: ${fixResult.backup_path}/`);
      console.log('Need help with the remaining findings? \u2192 bulwarkai.io');
      console.log('');

      // Fall through to start server with updated scan result
    }
  }

  // --json mode (without --fix): output JSON and exit
  if (FLAG_JSON && !FLAG_FIX) {
    const jsonOutput = { dashboard_version: version, ...r };
    process.stdout.write(JSON.stringify(jsonOutput, null, 2) + '\n');
    if (r.grade.startsWith('A') || r.grade.startsWith('B')) process.exit(0);
    if (r.grade === 'F') process.exit(2);
    process.exit(1); // C or D
  }

  // Use latest scan result (may have been updated by --fix)
  const currentResult = cachedScanResult;
  const currentSummary = currentResult.summary;

  // Build finding summary line
  const parts = [];
  if (currentSummary.critical > 0) parts.push(`${currentSummary.critical} critical`);
  if (currentSummary.high > 0) parts.push(`${currentSummary.high} high`);
  if (currentSummary.medium > 0) parts.push(`${currentSummary.medium} medium`);
  if (currentSummary.low > 0) parts.push(`${currentSummary.low} low`);
  const findingLine = parts.length > 0 ? parts.join(' \u00b7 ') : 'No issues found';

  // Startup banner
  const url = `http://localhost:${PORT}`;
  const iocCount = iocDatabase.skills.length;
  const patternCount = iocDatabase.detection_patterns ? iocDatabase.detection_patterns.length : 0;
  const cveData = safeParseJSON(safeReadFile(path.join(__dirname, 'ioc', 'cves.json')));
  const cveCount = cveData ? (cveData.total_cves || 0) : 0;

  // Banner helper: pad content to fixed width (49 inner chars)
  const W = 49;
  const row = (text) => `\u2502${(text + ' '.repeat(W)).slice(0, W)}\u2502`;
  const hr = (l, r) => `${l}${'\u2500'.repeat(W)}${r}`;

  const gradeLine = `   Grade:      ${currentResult.grade}  (${currentResult.score}/100)`;
  const iocLine = `   IOC database: ${iocCount}+ malicious skills`;
  const detLine = `   Detection:   ${patternCount} pattern rules, ${cveCount} CVEs`;

  console.log('');
  console.log(hr('\u250c', '\u2510'));
  console.log(row(''));
  console.log(row(`   \ud83e\udd9e BulwarkAI Security Scanner v${version}`));
  console.log(row(''));
  if (openclawDir) {
    console.log(row(`   Dashboard:  ${url}`));
    console.log(row(gradeLine));
    console.log(row(`   Findings:   ${findingLine}`));
  } else {
    console.log(row(`   Dashboard:  ${url}`));
    console.log(row('   OpenClaw:   Not detected'));
    console.log(row('   Set OPENCLAW_DIR or install to ~/.openclaw/'));
  }
  console.log(row(''));
  console.log(row(iocLine));
  console.log(row(detLine));
  if (FLAG_WATCH || FLAG_SERVICE) {
    console.log(row(`   Watch: every ${WATCH_INTERVAL}m`));
  }
  console.log(row(''));
  console.log(row('   Press Ctrl+C to stop'));
  console.log(row(''));
  console.log(row('   Need help fixing these? \u2192 bulwarkai.io'));
  if (!FLAG_SERVICE) {
    console.log(row(''));
    console.log(row('   For always-on monitoring:'));
    console.log(row('    npm i -g openclaw-security-dashboard'));
    console.log(row('    && openclaw-security-dashboard install'));
  }
  console.log(row(''));
  console.log(hr('\u2514', '\u2518'));
  console.log('');

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
    // Auto-open browser unless --no-browser or --service flag
    if (!FLAG_NO_BROWSER && !FLAG_SERVICE) {
      openBrowser(`http://localhost:${PORT}`);
    }

    // Start watcher if --watch or --service flag
    if (FLAG_WATCH || FLAG_SERVICE) {
      const { startWatcher } = require('./lib/watcher');
      startWatcher(WATCH_INTERVAL, () => {
        cachedScanResult = runFullScan();
        return cachedScanResult;
      });
    }
  });
}

// -----------------------------------------------------------------------------
// Subcommand Routing
// -----------------------------------------------------------------------------

const subcommand = args[0];
if (subcommand === 'install') {
  require('./lib/service').install();
} else if (subcommand === 'uninstall') {
  require('./lib/service').uninstall();
} else if (subcommand === 'status') {
  require('./lib/service').status();
} else {
  main();
}
