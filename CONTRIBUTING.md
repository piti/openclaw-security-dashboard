# Contributing to openclaw-security-dashboard

## Reporting Malicious Skills

If you've found a malicious skill not in our IOC database:

1. Open an issue with: skill name, publisher, technique used, evidence
2. Or submit a PR adding the entry to `ioc/malicious-skills.json`

## Reporting False Positives

If a legitimate skill is flagged:

1. Open an issue with: skill name, why it's legitimate, evidence

## Adding Security Checks

New checks should:
1. Run locally with zero network calls
2. Use only Node.js built-in modules
3. Return findings in the standard format: `{ severity, check, detail, remediation }`
4. Be added to the relevant panel in server.js

## Code Style

- Zero external dependencies
- Single-file architecture (server.js)
- Comments for each check section
