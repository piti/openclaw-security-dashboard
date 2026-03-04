# openclaw-security-dashboard

> Every OpenClaw dashboard shows what your agent *can* do.
> This one shows what it *shouldn't* be doing.

<!-- TODO: screenshot -->

## Quick Start

```bash
git clone https://github.com/bulwarkai/openclaw-security-dashboard.git
cd openclaw-security-dashboard
node server.js
# Open http://localhost:7177
```

Zero dependencies. Zero network calls. 100% local.

## What It Checks

**Gateway Security** — Bind address, auth enforcement, TLS, port exposure

**Skill Supply Chain** — IOC database cross-reference, ClawHavoc pattern detection

**Config Hardening** — File permissions, plaintext secrets, sandbox settings

**Identity Integrity** — SOUL.md tampering detection, prompt injection scanning

**Persistence & Cron** — LaunchAgents, hooks, MCP server version pinning

**Session Analysis** — Injection attempts, credential leaks in session logs

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
Antiy CERT, Snyk, and BulwarkAI's ongoing monitoring.

**1,184+ known malicious skills** across 16 categories.

The IOC database is MIT licensed. Use it in your own projects.

## API

`GET /api/status` returns JSON with your security grade, score, and panel statuses.
Other dashboards can integrate this endpoint.

`GET /api/scan` triggers a fresh scan and returns results.

`GET /api/baseline/accept` updates the identity file baseline to current hashes.

## Configuration

```bash
# Custom port
SECURITY_DASHBOARD_PORT=8080 node server.js

# Custom OpenClaw directory
OPENCLAW_DIR=/path/to/.openclaw node server.js
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

This dashboard provides automated detection. For expert analysis:
- [Security Blueprint ($97)](https://bulwarkai.io) — Hardened configs, audit scripts, IOC database, deployment guides
- [Security Audit ($497)](https://bulwarkai.io) — Personalized security report for your deployment

## License

MIT
