# openclaw-security-dashboard

![npm version](https://img.shields.io/npm/v/openclaw-security-dashboard?color=%23FF9F2E&style=flat-square)
![npm downloads](https://img.shields.io/npm/dw/openclaw-security-dashboard?color=%23FF9F2E&style=flat-square)
![license](https://img.shields.io/npm/l/openclaw-security-dashboard?color=%2322c55e&style=flat-square)

> Every OpenClaw dashboard shows what your agent *can* do.
> This one shows what it *shouldn't* be doing.

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

---

## What's New in v1.5

- **Built-in Audit Integration** — 8th panel runs `openclaw security audit --deep` automatically. One command = full coverage.
- **Accept Risk** — suppress false positives with hash-pinned exceptions that auto-expire if the file changes.
- **Credential Flow Mapping** — traces every API key from storage → agents → skills → exposure points.
- **SSRF Detection** — cloud metadata endpoints (CRITICAL), private IPs (HIGH), DNS rebinding (HIGH).
- **Sandbox Scoring** — scored 0-100 based on Docker state, network isolation, read-only FS, resource limits.
- **Capability Drift Detection** — tracks permission changes between scans. Alerts on privilege escalation.
- **Least-Privilege Engine** — identifies excess permissions per agent. "Agent X has exec but never uses it."
- **Network Policy Generator** — auto-generates UFW firewall rules for your deployment.
- **Hash-Chained Audit Trail** — tamper-evident SHA-256 chain. Modify the history and the chain breaks.
- **Signed Identity Baselines** — HMAC-signed. Tampered baselines trigger CRITICAL finding.
- **Memory Expansion** — scans daily notes, session transcripts, agent workspaces, and log files for 10 API key patterns.

---

## What It Checks — 8 Panels

| Panel | What It Checks |
|---|---|
| **Gateway Security** | Bind address, auth enforcement, TLS, port exposure, CVE version check |
| **Skill Supply Chain** | 1,184+ malicious IOCs, executables, ClickFix patterns, C2 IPs, publisher blacklist, reverse shell detection |
| **Config Hardening** | File permissions, plaintext secrets, sandbox scoring (0-100), safeBins, credential level (L0-L4), credential flow mapping |
| **Identity Integrity** | SHA-256 baselines with HMAC signatures, tamper detection, prompt injection scanning |
| **Persistence & Cron** | LaunchAgents, systemd services, cron jobs, hooks with network activity |
| **Session Analysis** | Injection attempts, credential leaks in session transcripts |
| **MCP Security** | Unpinned server versions, excessive server count, unauthorized configurations |
| **Built-in Audit** | Runs `openclaw security audit --deep` — surfaces 78 config checks alongside our panels |

### Credential Protection Levels

The scanner detects your credential protection level and shows the upgrade path:

| Level | Description | Risk |
|---|---|---|
| **L0** | Keys hardcoded in openclaw.json | Exposed — leaks into LLM context window |
| **L1** | env block with $VAR references | Basic — structurally separated |
| **L2** | Separate .env file | Good — config becomes secret-free |
| **L3** | credentials/ directory | Strong — scoped per-provider |
| **L4** | External vault (1Password, HashiCorp) | Excellent — keys never touch disk |

Deep dive: [Your OpenClaw API Keys Are Leaking — 5 Levels of Fix](https://bulwarkai.io/blog/openclaw-api-key-security)

### Credential Flow Mapping

For each API key, the scanner traces the full exposure path:

```
ANTHROPIC_API_KEY
  Storage: L1 (env block)  →  Agents: 3  →  Skills: 6  →  Model catalog: EXPOSED
  Risk: HIGH — key enters LLM context on every turn
```

### SSRF Detection

Skills are checked against known SSRF targets with tiered severity:

| Pattern | Severity |
|---|---|
| Cloud metadata endpoints (169.254.169.254, metadata.google.internal) | CRITICAL |
| Private IP ranges (10.x, 172.16.x, 192.168.x) | HIGH |
| DNS rebinding domains (.nip.io, .sslip.io) | HIGH |
| Regular external URLs | MEDIUM |

### Sandbox Scoring

Not just on/off — scored 0-100 with detailed breakdown:

```
Sandbox: STRONG (85/100)
  ✓ Docker running
  ✓ Network isolated (--network=none)
  ✓ Read-only filesystem
  ⚠ No resource limits set
```

### Capability Audit

Tracks permission changes between scans and flags over-permissioned agents:

```
⚠ Agent "main" gained 2 new tool(s): exec, browser_control
⚠ Agent "social-media" has exec access but hasn't used it in 30 days
```

### Network Policy Generator

Auto-generates firewall rules based on your actual configuration:

```
ALLOW (required for your setup):
  api.anthropic.com
  api.openai.com

BLOCK (recommended):
  169.254.169.254 (cloud metadata)
  Private IP ranges

UFW commands:
  sudo ufw default deny outgoing
  sudo ufw allow out to api.anthropic.com port 443
  ...
```

## Auto-Fix

```bash
npx openclaw-security-dashboard --fix
```

Creates a timestamped backup before touching anything. Fixes:

- Gateway bound to 0.0.0.0 → rebound to 127.0.0.1
- Weak file permissions → set to 600
- authBypass enabled → disabled
- Missing safeBins allowlist → added (11 safe commands)
- Plaintext API keys → replaced with env var references
- IOC-matched malicious skills → removed (with backup)
- ClickFix-detected skills → removed with confirmation (with backup)

After fixing, re-scans and shows your new grade. Typical improvement: F → B in one click.

Issues requiring human judgment are left as findings with remediation guidance.

## Accept Risk

Got a legitimate custom skill that triggers a finding? Suppress it:

- Click **"Accept Risk"** on any finding in the web UI
- Exception is **hash-pinned** — if the file content changes, the exception auto-expires
- IOC-matched malicious skills **cannot** be ignored (hardcoded blocklist)
- Acknowledged findings display at reduced opacity with "ACKNOWLEDGED" badge
- Acknowledged findings do **not** count toward your grade score
- Click **"Revoke"** to remove an exception at any time

Exceptions stored in `~/.openclaw/.dashboard-ignore.json`.

```bash
openclaw-security-dashboard --show-ignored   # include acknowledged findings in CLI output
```

## Hash-Chained Audit Trail

Every scan result is cryptographically linked to the previous one:

```json
{
  "scan_date": "2026-03-08T12:00:00Z",
  "grade": "B",
  "score": 72,
  "prev_hash": "sha256:a1b2c3...",
  "hash": "sha256:d4e5f6..."
}
```

If anyone tampers with the scan history, the chain breaks and a CRITICAL finding is generated.

## Signed Identity Baselines

Identity file baselines (SOUL.md, AGENTS.md, etc.) are signed with a machine-derived HMAC key. If the baseline file is modified directly (bypassing the "Accept Changes" flow), the signature check fails and a CRITICAL finding is generated.

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
openclaw-security-dashboard --show-ignored   # include acknowledged findings
```

Exit codes for `--json`: 0 (grade A/B), 1 (grade C/D), 2 (grade F).

## Background Service

`openclaw-security-dashboard install` sets up a persistent background service:

- **macOS:** LaunchAgent at `~/Library/LaunchAgents/io.bulwarkai.dashboard.plist`
- **Linux:** systemd user service at `~/.config/systemd/user/openclaw-security-dashboard.service`
- **Windows:** Not yet supported (use `npx` in a terminal)

Re-scans every 30 minutes. Starts on login. Restarts on crash.

- Logs: `~/.openclaw/.dashboard-logs/dashboard.log`
- Grade history: `~/.openclaw/.dashboard-logs/grade-history.jsonl` (hash-chained)

## Security & Permissions

This tool requires two system capabilities that security scanners like [Socket.dev](https://socket.dev) will flag:

**Shell access** — The scanner inspects your OpenClaw installation by running read-only system commands (`grep`, `stat`, `ls`, `crontab -l`, `lsof`). The `--fix` flag also runs `chmod` and file operations. All commands target only your `~/.openclaw/` directory.

**Network access** — The web dashboard runs a local HTTP server on `localhost:7177`. This server **only binds to loopback** (127.0.0.1) and **never makes outbound network connections**. No data leaves your machine. No telemetry. No phone-home.

Verify yourself:
```bash
lsof -iTCP:7177 -sTCP:LISTEN        # check what the server listens on
lsof -i -P | grep openclaw          # verify no outbound connections
```

## vs. Built-in `openclaw security audit`

The built-in audit has 78 config checks. This dashboard covers those plus the other 40%.

| Capability | Built-in Audit | openclaw-security-dashboard |
|---|---|---|
| Config checks (78 checks) | ✓ | ✓ Integrated as 8th panel |
| Security grade (A+ to F) | ✗ | ✓ |
| Malicious skill IOC database (1,184+) | ✗ | ✓ |
| Credential flow mapping | ✗ | ✓ Per-key tracing |
| SSRF detection | ✗ | ✓ Tiered severity |
| Sandbox scoring (0-100) | ✗ | ✓ |
| Identity hash baselines (signed) | ✗ | ✓ HMAC-signed |
| Capability drift detection | ✗ | ✓ Between scans |
| Least-privilege recommendations | ✗ | ✓ Per-agent |
| Network policy generation | ✗ | ✓ Auto UFW rules |
| Tamper-evident audit trail | ✗ | ✓ SHA-256 chain |
| Accept risk (false positives) | ✗ | ✓ Hash-pinned |
| Session log analysis | ✗ | ✓ |
| Persistence detection | ✗ | ✓ |
| MCP server audit | ✗ | ✓ |
| One-click auto-fix | Partial (permissions only) | ✓ 7 fix types |
| Always-on monitoring | ✗ | ✓ Re-scans every 30m |
| 100% local execution | ✓ | ✓ |
| Zero dependencies | ✓ | ✓ |

**Recommendation:** Run both. `openclaw security audit --deep` for config, then `npx openclaw-security-dashboard` for supply chain, identity, persistence, MCP, and everything else. Or just run the dashboard — v1.5 integrates the built-in audit automatically.

## API Integration

When running as a service, the dashboard exposes a JSON API on `localhost:7177`:

```bash
curl http://localhost:7177/api/status    # current grade + all panels
curl http://localhost:7177/api/scan      # trigger fresh scan
curl -X POST http://localhost:7177/api/fix   # apply auto-fixes
```

### Embed in your dashboard

```javascript
const res = await fetch('http://localhost:7177/api/status');
const { grade, score, grade_color, summary } = await res.json();
console.log(`Security: ${grade} (${score}/100)`);
```

### Embed widget

```html
<iframe src="http://localhost:7177/embed" width="320" height="130" frameborder="0"></iframe>
```

CORS enabled on all endpoints. API only binds to loopback.

### Full API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Current grade, score, panels, credential level |
| `/api/scan` | GET | Trigger fresh scan, return results |
| `/api/fix` | POST | Apply auto-fixes, return before/after |
| `/api/fixable` | GET | Count and list of auto-fixable findings |
| `/api/baseline/accept` | GET | Update identity baseline to current hashes |
| `/api/ignore` | GET | List current accept-risk exceptions |
| `/api/ignore` | POST | Add accept-risk exception |
| `/api/ignore` | DELETE | Remove accept-risk exception |
| `/api/watch` | GET | Watch mode status and interval |

## IOC Database

Open-source database of known malicious OpenClaw skills, publishers, C2 domains, SSRF indicators, and sandbox escape patterns. Sources: Koi Security, Antiy CERT, Snyk, Bitdefender, BulwarkAI.

**1,184+ known malicious skills** across 16 categories.

MIT licensed. Use it in your own projects. PRs welcome.

## Security Grade

| Severity | Score Impact |
|---|---|
| CRITICAL | -25 each |
| HIGH | -15 each |
| MEDIUM | -5 each |
| LOW | -2 each |

Acknowledged (accepted risk) findings do not count toward the score.

## Configuration

```bash
SECURITY_DASHBOARD_PORT=8080 npx openclaw-security-dashboard   # custom port
OPENCLAW_DIR=/path/to/.openclaw npx openclaw-security-dashboard # custom dir
```

## FAQ

**Does this replace `openclaw security audit`?**
No — it integrates it. v1.5 runs the built-in audit as the 8th panel automatically. You get both our checks and theirs in one command.

**Does this send data anywhere?**
No. Zero network calls. Your config never leaves your machine.

**Can I use the IOC database in my own project?**
Yes. MIT licensed. Credit appreciated.

**How do I update?**
```bash
npm update -g openclaw-security-dashboard
```

**How do I suppress a false positive?**
Click "Accept Risk" on the finding in the web UI. The exception is hash-pinned — if the file changes, the finding comes back.

**Where are the logs?**
`~/.openclaw/.dashboard-logs/dashboard.log` and `grade-history.jsonl` (hash-chained).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to:
- Report new malicious skills
- Report false positives
- Add new security checks
- Improve the dashboard UI

## About

Built by [BulwarkAI](https://bulwarkai.io) — security hardening for OpenClaw deployments.

- Website: [bulwarkai.io](https://bulwarkai.io)
- Dashboard page: [bulwarkai.io/dashboard](https://bulwarkai.io/dashboard)
- Blog: [bulwarkai.io/blog](https://bulwarkai.io/blog)
- X/Twitter: [@BulwarkAI](https://x.com/BulwarkAI)

## License

MIT
