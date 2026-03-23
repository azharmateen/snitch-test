# snitch-test

Security tool that tests if your project dependencies are stealing environment variables. It creates a Docker sandbox with fake (canary) credentials, installs your dependencies, and monitors for credential exfiltration.

## How It Works

1. **Detect** - Identifies your project type (Python/Node/Ruby) and install command
2. **Canary** - Generates realistic-looking fake credentials (AWS keys, DB passwords, API tokens)
3. **Sandbox** - Builds a Docker container with canary env vars and your project dependencies
4. **Monitor** - Captures all network traffic during dependency installation
5. **Analyze** - Checks if any canary values appear in outbound traffic
6. **Report** - Generates a risk assessment with actionable findings

## Installation

```bash
pip install snitch-test
```

**Requirements:** Docker must be installed and running.

## Usage

```bash
# Scan current project
snitch-test scan

# Scan a specific directory
snitch-test scan /path/to/project

# Output as JSON (for CI)
snitch-test scan -f json

# Output as SARIF (for GitHub Security tab)
snitch-test scan -f sarif -o results.sarif

# Output as Markdown
snitch-test scan -f markdown -o report.md

# Dry run (show what would happen without Docker)
snitch-test scan --dry-run

# View last report
snitch-test report

# Show sample canary credentials
snitch-test canaries
```

## What Gets Tested

The tool generates 18+ realistic canary credentials across categories:

| Category | Credentials |
|----------|------------|
| Cloud | AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, GOOGLE_APPLICATION_CREDENTIALS_JSON, AZURE_CLIENT_SECRET |
| Database | DATABASE_URL (PostgreSQL), REDIS_URL, MONGODB_URI |
| API | OPENAI_API_KEY, STRIPE_SECRET_KEY, SENDGRID_API_KEY, TWILIO_AUTH_TOKEN, GITHUB_TOKEN, SLACK_BOT_TOKEN |
| Crypto | SECRET_KEY, JWT_SECRET, ENCRYPTION_KEY, SSH_PRIVATE_KEY |
| Email | SMTP_PASSWORD |

## Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| Safe | 0 | No suspicious activity |
| Low | 1-24 | Minor concerns, review recommended |
| Medium | 25-49 | Suspicious patterns found |
| High | 50-79 | Active suspicious network activity |
| Critical | 80-100 | Credential exfiltration detected |

## CI Integration

```yaml
# GitHub Actions
- name: Dependency Security Scan
  run: |
    pip install snitch-test
    snitch-test scan -f sarif -o snitch.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: snitch.sarif
```

## How It Catches Malicious Packages

- **Install-time scripts** - `postinstall` (npm), `setup.py` (Python) that run during `pip install`/`npm install`
- **Environment scanning** - Packages that read `os.environ` or `process.env` during install
- **Network exfiltration** - Outbound HTTP/DNS requests containing credential values
- **Obfuscated theft** - Base64-encoded, hex-encoded, or chunked credential transmission

## Limitations

- Requires Docker to be running
- Cannot detect runtime-only theft (only tests install-time behavior)
- Network monitoring captures Docker bridge traffic (some advanced exfiltration via DNS tunneling may be missed)
- Build times depend on the number of dependencies

## License

MIT
