# WRAITH

**W**eb **R**econnaissance, **A**ssessment, **I**nspection & **T**hreat **H**unting — a modular
web application vulnerability scanner for authorized penetration testing, built for Kali Linux.

> ⚠️ **Authorized testing only.** Only scan systems you own or have explicit written permission
> to test. WRAITH confines itself to the declared scope, refuses to start without an explicit
> authorization affirmation, and records that affirmation in an audit log.

## Installation (Linux)

WRAITH needs **Python 3.11 or newer** (preinstalled on Kali Linux) and runs on any Linux. The
recommended way to install it is with [`pipx`](https://pypa.github.io/pipx/), which puts the
`wraith` command on your `PATH` inside its own isolated virtual environment.

### 1. Check your Python version

```bash
python3 --version      # must be 3.11 or newer
```

If it is older than 3.11, install a newer Python (e.g. `sudo apt install python3.11` on
Debian/Ubuntu, or use `pyenv`).

### 2. Install pipx

**Kali / Debian / Ubuntu:**

```bash
sudo apt update
sudo apt install -y pipx git
pipx ensurepath
```

**Fedora:**

```bash
sudo dnf install -y pipx git
pipx ensurepath
```

**Any Linux (via pip):**

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

`pipx ensurepath` adds `~/.local/bin` to your `PATH`. **Open a new terminal** (or run
`source ~/.bashrc`) afterwards so the `wraith` command is found.

### 3. Get the code and install

```bash
git clone https://github.com/IanNarito/WRAITH.git
cd WRAITH
pipx install .
```

That's it — `wraith` is now installed globally for your user. (System TLS libraries and
`openssl`, already present on Kali and most distros, are used by the TLS check.)

### 4. Verify the installation

```bash
wraith --version
wraith list-checks        # lists every check and whether it is on by default
wraith scan --help        # full help for the scan command
```

### Upgrading and uninstalling

```bash
cd WRAITH && git pull && pipx install --force .   # upgrade to the latest code
pipx uninstall wraith                             # remove it
```

### Development install (for running the tests / hacking on WRAITH)

```bash
git clone https://github.com/IanNarito/WRAITH.git
cd WRAITH
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest            # run the test suite
ruff check .      # lint
mypy              # type-check
```

Run it from the venv with `python -m wraith scan ...` (or just `wraith ...` while the venv is
active).

## Usage

### The basics

WRAITH has two commands:

```bash
wraith scan <target> [options]     # run a scan
wraith list-checks                 # list available checks
```

A scan always needs a **target** and your **authorization**. The simplest run:

```bash
wraith scan https://target.example --confirm-authorized
```

This runs the default (passive + read-only) checks against `https://target.example`, confines
itself to the `target.example` host, throttles to 5 requests/second, and prints a colored report
to your terminal. Without `--confirm-authorized` it will ask you to confirm interactively (and
refuse to run in a script/pipeline until you pass the flag).

> ⚠️ Only scan systems you own or have **explicit written permission** to test.

### A typical engagement

```bash
# 1. Passive recon first — see what's there, save an HTML report for the client.
wraith scan https://app.target.example \
  --scope "app.target.example,*.target.example" \
  --confirm-authorized \
  --rate 5 --concurrency 10 \
  --format html --output recon.html

# 2. Active testing — turn on the injection checks, crawl deeper, chain through Burp,
#    and correlate detected versions against known CVEs.
wraith scan https://app.target.example \
  --scope "app.target.example" \
  --confirm-authorized \
  --aggressive \
  --crawl-depth 2 \
  --cve \
  --proxy http://127.0.0.1:8080 \
  --format html --output full.html \
  -v
```

### Safe mode vs. aggressive mode

- **Safe mode (default):** only non-mutating requests (GET/HEAD/OPTIONS). Runs recon plus the
  passive and read-only checks. Safe to run against production.
- **Aggressive mode (`--aggressive`):** additionally runs the active injection checks (XSS, SQLi,
  command injection, SSTI, LDAP injection, path traversal, open redirect, SSRF, XXE, CRLF,
  host-header), which send crafted values into parameters and may POST forms. Still scope-confined,
  rate-limited, and non-destructive — but use it on systems and in windows where active testing is
  authorized.

### Flag reference

Run `wraith scan --help` for the authoritative list. Grouped by purpose:

**Target & scope**

| Flag | Default | Description |
|---|---|---|
| `target` (positional) | — | Base URL to scan. `https://` is assumed if you omit the scheme. |
| `--scope <rules>` | the target host | Comma-separated in-scope rules: exact `host`, `host:port`, `*.wildcard.glob`, or `re:<regex>` (matched against the host). Anything outside is blocked and never requested. |

**Authorization & safety**

| Flag | Default | Description |
|---|---|---|
| `--confirm-authorized` | off | Affirm you have permission to test. Required for non-interactive runs; otherwise you're prompted. Recorded in the audit log. |
| `--safe-mode` / `--aggressive` | `--safe-mode` | Safe allows only non-mutating requests. Aggressive enables the active injection checks. |
| `--rate <n>` | `5` | Maximum requests per second (global token bucket shared by all checks). |
| `--concurrency <n>` | `10` | Maximum simultaneous requests. |
| `--timeout <seconds>` | `10` | Per-request timeout. |

**Check selection**

| Flag | Default | Description |
|---|---|---|
| `--checks <names>` | all default-on | Comma-separated list of checks to run (overrides the defaults). Names come from `wraith list-checks`. |
| `--exclude <names>` | — | Comma-separated checks to skip. |

**Crawling**

| Flag | Default | Description |
|---|---|---|
| `--crawl-depth <n>` | `1` | Same-origin crawl depth. `1` = links on the target page only; higher values follow links further (GET-only). |
| `--max-pages <n>` | `30` | Maximum number of pages to crawl. |

**Authentication** (see [Authenticated scanning](#authenticated-scanning))

| Flag | Default | Description |
|---|---|---|
| `--login-url <url>` | — | Form-login endpoint; WRAITH logs in and scans with the resulting session. |
| `--login-data <field=value>` | — | A login form field (repeatable), e.g. `--login-data user=admin --login-data pass=secret`. |
| `--login-check <text>` | — | Substring expected in the post-login response to confirm success (login failure aborts the scan). |

**CVE correlation** (see [CVE correlation](#cve-correlation---cve))

| Flag | Default | Description |
|---|---|---|
| `--cve` / `--no-cve` | `--no-cve` | Look up detected product versions against NVD. Contacts NVD, **not** the target. |
| `--nvd-api-key <key>` | `$NVD_API_KEY` | Optional NVD API key for a higher lookup rate limit. |
| `--cve-cache <dir>` | — | Directory to cache NVD results between runs. |

**Request options**

| Flag | Default | Description |
|---|---|---|
| `--proxy <url>` | — | Route HTTP traffic through an upstream proxy, e.g. `http://127.0.0.1:8080` for Burp/ZAP. (Raw TLS probes connect directly.) |
| `--user-agent <string>` | `WRAITH/…` | Override the User-Agent header. |
| `--header "Name: value"` | — | Add a request header (repeatable). Use for bearer tokens, e.g. `--header "Authorization: Bearer …"`. |
| `--cookie "name=value"` | — | Add a cookie (repeatable). Use for session-cookie auth. |

**Output & reporting**

| Flag | Default | Description |
|---|---|---|
| `--format <fmt>` | `terminal` | `terminal`, `json`, `html`, or `sarif`. |
| `--output <file>` | stdout | Write the report to a file instead of the terminal. |
| `--fail-on <severity>` | — | Exit with code `1` if any finding is at or above this severity (`info`/`low`/`medium`/`high`/`critical`). For CI gating. |
| `-v` / `-vv` | off | `-v` shows progress and prints evidence in the terminal report; `-vv` adds debug logging. |

**Logging & config**

| Flag | Default | Description |
|---|---|---|
| `--audit-log <file>` | `./wraith-audit-<UTC>.log` | Where to write the audit log (operator, authorization, every scope decision and request). |
| `--config <file>` | — | YAML file of defaults (see below). Command-line flags always win. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no findings at or above `--fail-on`. |
| `1` | Scan completed; findings at or above `--fail-on`. |
| `2` | Scan error, or an incomplete scan (a check failed, bad input, authorization declined). |

Example CI gate: `wraith scan https://app.example --confirm-authorized --fail-on medium`
fails the pipeline if any medium-or-higher issue is found.

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
| `csrf` | State-changing (POST) forms with no anti-CSRF token | Passive form inspection only; a form with a known token field name (`data/csrf_tokens.txt`) or a random hidden token is treated as protected; MEDIUM/PROBABLE |

### Aggressive checks (require `--aggressive`)

These send crafted values into query and form parameters, so they run only under `--aggressive`.
They stay in scope, obey the rate limit, and use non-destructive probes (no data extraction, no
time delays). Findings are `probable` — confirm manually.

| Check | What it looks for | Technique |
|---|---|---|
| `xss_reflected` | Reflected cross-site scripting | Unique marker reflected unencoded into HTML; non-executing tag, not a live script |
| `xss_stored` | Stored/persistent XSS | Submits a non-executing marker to each form once, re-checks pages for unencoded persistence |
| `sqli` | SQL injection | Error-based, strict boolean-differential, and tightly-bounded time-based blind (one sleeping request confirmed by a fast control) |
| `command_injection` | OS command injection | Echo-marker differential (token returned without the literal `echo` text = execution, CONFIRMED), plus budgeted time-based blind confirmed by a fast control |
| `ssti` | Server-side template injection | Injects `a*b` in each engine's delimiters (`{{ }}`, `${ }`, `#{ }`, `<%= %>`, …); flags only when the product renders and the literal expression does not (CONFIRMED) |
| `ldap_injection` | LDAP injection | Error-based: filter-breaking values that surface a new LDAP error signature (`data/ldap_errors.txt`) absent from the baseline; PROBABLE |
| `path_traversal` | Path traversal / LFI | Reads `/etc/passwd` or `win.ini` (harmless marker files), confirmed by content signature |
| `open_redirect` | Unvalidated redirects | Injects a reserved-domain marker; flags redirects to it (never followed) |
| `ssrf` | Server-side request forgery | Conservative in-band only: an unresolvable `*.invalid` marker + a fetch-error differential (no third party ever contacted, no OOB) |
| `xxe` | XML external entity | Internal-entity expansion only (no external entities / DTD fetch / DoS); MEDIUM/PROBABLE |
| `crlf_injection` | HTTP response splitting | Injects CR-LF + marker header; confirmed if emitted as a real response header |
| `host_header_injection` | Host-header poisoning | Spoofs Host/X-Forwarded-Host; flags reflection into body/Location |
| `idor` | Enumerable object references / IDOR candidates (off by default) | Numeric id-like params only: a neighbour id returns a same-shaped but different record while an out-of-range id clearly differs; PROBABLE — confirm with a second account |
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
