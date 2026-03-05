# openclaw-security-dashboard

![npm version](https://img.shields.io/npm/v/openclaw-security-dashboard?color=%23FF9F2E&style=flat-square)
![npm downloads](https://img.shields.io/npm/dw/openclaw-security-dashboard?color=%23FF9F2E&style=flat-square)
![license](https://img.shields.io/npm/l/openclaw-security-dashboard?color=%2322c55e&style=flat-square)

> Every OpenClaw dashboard shows what your agent *can* do.
> This one shows what it *shouldn't* be doing.

<!-- TODO: screenshot -->

## Install & Run

**Install permanently (recommended):**
```bash
npm install -g openclaw-security-dashboard
openclaw-security-dashboard install
```
Dashboard runs at http://localhost:7177, starts on login, re-scans every 30 minutes.

**Quick scan (one-off):**
```bash
npx openclaw-security-dashboard@latest
```

**Auto-fix:**
```bash
openclaw-security-dashboard --fix       # installed globally
npx openclaw-security-dashboard --fix   # or via npx
```

Zero dependencies. Zero network calls. Everything stays on your machine.

**Management commands:**
```bash
openclaw-security-dashboard status      # check if running, current grade
openclaw-security-dashboard uninstall   # stop and remove service
```

### Or clone for development

```bash
git clone https://github.com/piti/openclaw-security-dashboard.git
cd openclaw-security-dashboard
node server.js
```

## Auto-Fix

```bash
# Scan, fix what's fixable, show before/after
npx openclaw-security-dashboard --fix

# Fix + JSON output (for CI/CD)
npx openclaw-security-dashboard --fix --json
```

Creates a timestamped backup before touching anything. Fixes mechanical issues automatically:

- Gateway bound to 0.0.0.0 → rebound to 127.0.0.1
- Weak file permissions → set to 600
- authBypass enabled → disabled
- Missing safeBins allowlist → added (11 safe commands)
- Plaintext API keys → replaced with env var references

After fixing, re-scans and shows your new grade. Typical improvement: F → C in seconds.

Issues requiring human judgment (skill selection, identity files, network config) are left as findings with remediation guidance.

The browser dashboard also has an **Auto-Fix button** with a confirmation modal — click it to see exactly what will change, then apply with one click.

## CLI Flags & Subcommands

```bash
# Subcommands
openclaw-security-dashboard install          # install as background service
openclaw-security-dashboard uninstall        # stop and remove service
openclaw-security-dashboard status           # check if running + current grade

# Flags
openclaw-security-dashboard --fix            # scan + auto-fix
openclaw-security-dashboard --json           # JSON output + exit (for CI/CD)
openclaw-security-dashboard --no-browser     # start server without opening browser
openclaw-security-dashboard --watch          # re-scan periodically (default: 30m)
openclaw-security-dashboard --watch-interval 15  # custom watch interval (minutes)
openclaw-security-dashboard --fix --json     # fix + JSON output
```

Exit codes for `--json`: 0 (grade A/B), 1 (grade C/D), 2 (grade F).

## Background Service

`openclaw-security-dashboard install` sets up a persistent background service:

- **macOS:** LaunchAgent at `~/Library/LaunchAgents/io.bulwarkai.dashboard.plist` — starts on login, restarts on crash
- **Linux:** systemd user service at `~/.config/systemd/user/openclaw-security-dashboard.service`
- **Windows:** Not yet supported (use `npx` in a terminal)

The service re-scans every 30 minutes and tracks grade history:
- Logs: `~/.openclaw/.dashboard-logs/dashboard.log`
- Grade history: `~/.openclaw/.dashboard-logs/grade-history.jsonl`

The `status` command also checks npm for newer versions and prompts to update.

## Security & Permissions

This tool requires two system capabilities that security scanners like [Socket.dev](https://socket.dev) will flag:

**Shell access** — The scanner inspects your OpenClaw installation by running read-only system commands (`grep`, `stat`, `ls`, `crontab -l`, `lsof`). The `--fix` flag also runs `chmod` and file operations to apply security fixes. All commands target only your `~/.openclaw/` directory.

**Network access** — The web dashboard UI runs a local HTTP server on `localhost:7177`. This server **only binds to loopback** (127.0.0.1) and **never makes outbound network connections**. No data leaves your machine. No telemetry. No phone-home.

You can verify this yourself:
```bash
# Check what the server listens on
lsof -iTCP:7177 -sTCP:LISTEN
# Verify no outbound connections
lsof -i -P | grep openclaw
```

## What It Checks

**Gateway Security** — Bind address, auth enforcement, TLS, port exposure, CVE version check

**Skill Supply Chain** — 102+ named IOCs, 21 pattern rules, C2 IP detection, exfil domain detection, publisher blacklist, reverse shell detection

**Config Hardening** — File permissions, plaintext secrets, sandbox settings

**Identity Integrity** — SOUL.md tampering detection, prompt injection scanning, SHA-256 hash baselines

**Persistence & Cron** — LaunchAgents, hooks, MCP server version pinning

**Session Analysis** — Injection attempts, credential leaks in session logs

## API Integration

When running as a service (`openclaw-security-dashboard install`), the dashboard exposes a JSON API on `localhost:7177`.

### Get current security status

```bash
curl http://localhost:7177/api/status
```

Returns:

```json
{
  "dashboard_version": "1.4.2",
  "scan_date": "2026-03-05T12:00:00Z",
  "openclaw_version": "2026.3.2",
  "grade": "B",
  "score": 72,
  "grade_color": "#3b82f6",
  "credential_level": {
    "level": "L3",
    "label": "Credentials directory"
  },
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 1,
    "total": 3
  },
  "panels": {
    "gateway": { "status": "green" },
    "skills": { "status": "green" },
    "config": { "status": "amber" },
    "identity": { "status": "green" },
    "persistence": { "status": "green" },
    "sessions": { "status": "green" },
    "mcp": { "status": "green" }
  }
}
```

### Trigger a rescan

```bash
curl http://localhost:7177/api/scan
```

### Apply auto-fixes

```bash
curl -X POST http://localhost:7177/api/fix
```

### Embed in your dashboard

```javascript
// Fetch security grade for your OpenClaw dashboard
const res = await fetch('http://localhost:7177/api/status');
const { grade, score, grade_color, summary } = await res.json();

// Display a security badge
console.log(`Security: ${grade} (${score}/100)`);
```

The API only binds to loopback (127.0.0.1). No authentication required for local access. No data leaves your machine.

## Security Grade

Your deployment gets a letter grade (A+ through F) based on weighted findings.
The grade is designed to be screenshot-friendly — share your score.

| Severity | Score Impact |
|----------|-------------|
| CRITICAL | -25 each |
| HIGH | -15 each |
| MEDIUM | -5 each |
| LOW | -2 each |

## Integration with Other Dashboards

openclaw-security-dashboard works alongside Mission Control, TenacitOS, ClawDeck,
and any other OpenClaw dashboard. Three integration methods:

### Automatic (zero config)
Every scan writes `~/.openclaw/.security-status.json` with your grade, score,
and panel statuses. Any dashboard that reads `~/.openclaw/` can display this data.

### Embed Widget
Drop this into any dashboard:
```html
<iframe src="http://localhost:7177/embed" width="320" height="130" frameborder="0"></iframe>
```
Supports `?theme=light` for light-themed dashboards.

### JSON API
Fetch security data from your dashboard's code:
```javascript
const res = await fetch('http://localhost:7177/api/status');
const { grade, score, panels } = await res.json();
```

CORS is enabled on all endpoints.

## IOC Database

This project maintains an open-source database of known malicious OpenClaw skills,
publishers, C2 domains, and credential patterns. Sources include Koi Security,
Antiy CERT, Snyk, Bitdefender, and BulwarkAI's ongoing monitoring.

**1,184+ known malicious skills** across 16 categories.

The IOC database is MIT licensed. Use it in your own projects.

## API

`GET /api/status` returns JSON with your security grade, score, and panel statuses.

`GET /api/scan` triggers a fresh scan and returns results.

`POST /api/fix` applies auto-fixes and returns before/after comparison with backup path.

`GET /api/fixable` returns the count and list of auto-fixable findings (read-only).

`GET /api/baseline/accept` updates the identity file baseline to current hashes.

## Configuration

```bash
# Custom port
SECURITY_DASHBOARD_PORT=8080 npx openclaw-security-dashboard

# Custom OpenClaw directory
OPENCLAW_DIR=/path/to/.openclaw npx openclaw-security-dashboard
```

## FAQ

**Does this replace `openclaw security audit`?**
No. The built-in audit is good but misses ~40% of the threat surface. This dashboard
covers the gap: multi-directory skill scanning, IOC cross-reference, identity integrity,
persistence detection, and session analysis.

**Does this send data anywhere?**
No. Everything runs locally. Zero network calls. Your config never leaves your machine.

**Can I use the IOC database in my own project?**
Yes. MIT licensed. Credit appreciated.

**How do I update?**
`npm update -g openclaw-security-dashboard` — the service picks up the new version on next restart.

**How do I check if it's running?**
`openclaw-security-dashboard status` — shows grade, watch interval, next scan, and version.

**Where are the logs?**
`~/.openclaw/.dashboard-logs/dashboard.log` — grade history in `grade-history.jsonl` in the same directory.

**I found a false positive / want to report a malicious skill.**
Open an issue or PR. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to:
- Report new malicious skills
- Report false positives
- Add new security checks
- Improve the dashboard UI

## About

Built by [BulwarkAI](https://bulwarkai.io) — security hardening for OpenClaw deployments.

## License

MIT
