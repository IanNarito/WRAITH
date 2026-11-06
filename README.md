# WRAITH

**W**eb **R**econnaissance, **A**ssessment, **I**nspection & **T**hreat **H**unting — a modular
web application vulnerability scanner for authorized penetration testing, built for Kali Linux.

> ⚠️ **Authorized testing only.** Only scan systems you own or have explicit written permission
> to test. WRAITH confines itself to the declared scope and requires `--confirm-authorized`.

## Status

v1 in progress. Working end to end: scope confinement, rate-limited HTTP client (proxy, safe
mode, evidence capture), discovery (robots.txt, sitemap.xml, same-origin links one level deep,
forms, tech hints), plugin registry, and the `security_headers` check with terminal output.

Coming next: TLS, exposed files, tech fingerprint, CORS, and cookie checks; JSON/HTML reports;
audit log.

## Install

```bash
pipx install .
```

Development:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
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

Options can also come from a YAML file (`--config wraith.yaml`); flags on the command line win.
The target and `--confirm-authorized` are deliberately not accepted from a file.

Exit codes: `0` no findings at/above `--fail-on`, `1` findings at/above it, `2` scan error.
