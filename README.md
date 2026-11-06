# WRAITH

**W**eb **R**econnaissance, **A**ssessment, **I**nspection & **T**hreat **H**unting — a modular
web application vulnerability scanner for authorized penetration testing, built for Kali Linux.

> ⚠️ **Authorized testing only.** Only scan systems you own or have explicit written permission
> to test. WRAITH confines itself to the declared scope, refuses to start without an explicit
> authorization affirmation, and records that affirmation in an audit log.

## Install

Requires Python 3.11+ (preinstalled on Kali).

```bash
pipx install .            # from a checkout; puts `wraith` on your PATH
```

Development:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check . && mypy
```

## Usage

```bash
wraith scan https://target.example \
  --scope "target.example,*.target.example" \
  --confirm-authorized \
  --rate 5 --concurrency 10 \
  --format html --output report.html \
  --proxy http://127.0.0.1:8080 -v

wraith list-checks
```

| Flag | Purpose |
|---|---|
| `target` | Base URL (`https://` is assumed if no scheme is given) |
| `--scope` | Comma-separated rules: `host`, `host:port`, `*.glob`, `re:<regex>`. Default: the target host |
| `--confirm-authorized` | Affirm permission to test. Without it WRAITH asks interactively, or exits when non-interactive |
| `--rate` / `--concurrency` | Requests per second (default 5) and max parallel requests (default 10) |
| `--checks` / `--exclude` | Select or drop checks by name |
| `--format` / `--output` | `terminal` (default), `json`, `html`, `sarif`; file destination (stdout if omitted) |
| `--proxy` | Route HTTP traffic through Burp/ZAP |
| `--timeout`, `--user-agent`, `--header`, `--cookie` | Request options (`--header`/`--cookie` repeatable) |
| `--safe-mode` / `--aggressive` | Safe (default) allows only GET/HEAD/OPTIONS |
| `--fail-on` | Severity threshold for exit code 1 |
| `--audit-log` | Audit log path. Default: `./wraith-audit-<UTC timestamp>.log` |
| `--config` | YAML file of defaults; command-line flags win |
| `-v` / `-vv` | Show progress / debug output; `-v` also prints evidence in the terminal report |

Exit codes: `0` no findings at/above `--fail-on`, `1` findings at/above it, `2` scan error or
an incomplete scan (a check failed). For example, gate a pipeline with `--fail-on medium`.

### Config file

```yaml
# wraith.yaml
scope: [target.example, "*.target.example"]
rate: 3
format: json
output: report.json
headers:
  X-Engagement-ID: ACME-2026-11
cookies:
  session: "..."
```

The target and `--confirm-authorized` are deliberately not accepted from a file.

## Checks (v1)

| Check | What it looks for | How it avoids false positives |
|---|---|---|
| `security_headers` | Missing/weak CSP, HSTS, clickjacking protection, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Directly observed headers; CSP parsed per spec (nonces, `strict-dynamic`, `<meta>` policies) |
| `tls_config` | Expired / self-signed / mismatched certificates, TLS 1.0/1.1, weak ciphers, plain HTTP | Real handshakes; a probe the local OpenSSL can't run reports nothing |
| `exposed_files` | `.git`, `.env`, backups, dumps, keys, phpinfo, actuator… (`data/exposed_paths.txt`) | 200 **and** a content signature match; catch-all/soft-404 baseline; HTML pages ignored for non-HTML files |
| `tech_fingerprint` | Server, framework, CMS, JS libraries and exposed versions (`data/tech_signatures.yaml`) | Version findings are informational, with an NVD link for CVE cross-checking |
| `cors` | Arbitrary origin reflection, `null` origin, prefix/suffix allowlist bypasses, `*` with credentials | Exact match of the probe origin in `Access-Control-Allow-Origin` |
| `cookies` | Session cookies missing `Secure`, `HttpOnly`, `SameSite` (or `SameSite=None`) | Only session-like cookies (`data/session_cookies.txt`); CSRF tokens and deletions skipped |

### Aggressive checks (require `--aggressive`)

These send crafted values into query and form parameters, so they run only under `--aggressive`.
They stay in scope, obey the rate limit, and use non-destructive probes (no data extraction, no
time delays). Findings are `probable` — confirm manually.

| Check | What it looks for | Technique |
|---|---|---|
| `xss_reflected` | Reflected cross-site scripting | Unique marker reflected unencoded into HTML; non-executing tag, not a live script |
| `xss_stored` | Stored/persistent XSS | Submits a non-executing marker to each form once, re-checks pages for unencoded persistence |
| `sqli` | SQL injection | Error-based, strict boolean-differential, and tightly-bounded time-based blind (one sleeping request confirmed by a fast control) |
| `path_traversal` | Path traversal / LFI | Reads `/etc/passwd` or `win.ini` (harmless marker files), confirmed by content signature |
| `open_redirect` | Unvalidated redirects | Injects a reserved-domain marker; flags redirects to it (never followed) |
| `ssrf` | Server-side request forgery | Conservative in-band only: an unresolvable `*.invalid` marker + a fetch-error differential (no third party ever contacted, no OOB) |
| `xxe` | XML external entity | Internal-entity expansion only (no external entities / DTD fetch / DoS); MEDIUM/PROBABLE |
| `crlf_injection` | HTTP response splitting | Injects CR-LF + marker header; confirmed if emitted as a real response header |
| `host_header_injection` | Host-header poisoning | Spoofs Host/X-Forwarded-Host; flags reflection into body/Location |
| `content_discovery` | Unlinked paths (off by default) | Small wordlist brute force, GET-only, soft-404 calibration, request budget |
| `param_mining` | Hidden parameters (off by default) | Many candidate names per request; flags reflected unknown parameters |

**DoS safety:** all checks share one HTTP client whose global token-bucket rate limit
(`--rate`, default 5/s) and concurrency cap (`--concurrency`) bound the *total* request rate,
so adding checks never increases load. Active checks are non-destructive (no data extraction,
no stacked queries; time-based SQLi is strictly budgeted) and verify a differential before
reporting. `content_discovery` and `param_mining` are off by default — enable with `--checks`.

### Authenticated scanning

Scan as a logged-in user. For token/cookie auth, pass `--header "Authorization: Bearer ..."` or
`--cookie "session=..."`. For form login:

```bash
wraith scan https://app.example --confirm-authorized --aggressive \
  --login-url https://app.example/login \
  --login-data username=admin --login-data password=secret \
  --login-check "Dashboard"
```

WRAITH logs in first (scope-checked, audit-logged), verifies the `--login-check` substring, and
runs the scan with the resulting session.

### CVE correlation (`--cve`)

With `--cve`, detected product versions are looked up against the NVD CVE database and matching
CVEs are reported, severity set from the highest CVSS. This contacts **NVD, not the target**,
over a separate client; only the product/version/CPE is sent, results are cached (`--cve-cache`),
and any network failure degrades to no data. Set `--nvd-api-key` (or `NVD_API_KEY`) for a higher
rate limit.

```bash
# Full engagement: crawl deeper, enable injection checks and CVE lookup.
wraith scan https://target.example --confirm-authorized \
  --aggressive --crawl-depth 2 --cve --format html --output report.html
```

Adding a check: drop a `BaseCheck` subclass into `wraith/checks/`. It is discovered
automatically; nothing else needs wiring.

## Safety controls

- **Scope confinement:** every request, every redirect hop, and every raw TLS handshake is
  checked against the scope first. Off-scope requests are blocked and logged, never sent.
  Off-scope links found during discovery are recorded but not requested.
- **Safe mode (default):** only non-mutating methods. Discovery also never follows links that
  look state-changing (logout, delete, reset...), even with GET.
- **Rate limiting:** a global token bucket plus a concurrency cap, shared by every check.
- **Audit log:** UTC-timestamped record of the operator, the authorization affirmation, every
  scope decision, and every request.

## Reports

- `terminal`: grouped by severity with a summary.
- `json`: stable, versioned schema (`schema_version`), finding IDs stable across scans for diffing.
- `html`: one self-contained file with collapsible evidence, for client deliverables.
- `sarif`: SARIF 2.1.0 for CI and code-scanning dashboards.

Every finding has a severity, a confidence (confirmed / probable / informational), the affected
URL, a description, remediation, and evidence (the exact request and the response snippet).

## Known limitations

- Raw TLS probes connect directly to the target, not through `--proxy` (a warning is shown).
- Weak-protocol/cipher detection depends on what the local OpenSSL build can still offer.
- SSRF detection is in-band and conservative (no out-of-band collaborator), so it finds only
  cases that surface a server-side fetch error; blind SSRF needs manual confirmation.
- XXE proves internal-entity expansion only; external-entity exploitation needs manual testing.
- DOM-based XSS and second-order injection are not covered.
