# WRAITH

**W**eb **R**econnaissance, **A**ssessment, **I**nspection & **T**hreat **H**unting — a modular
web application vulnerability scanner for authorized penetration testing, built for Kali Linux.

> ⚠️ **Authorized testing only.** Only scan systems you own or have explicit written permission
> to test. WRAITH confines itself to the declared scope and requires `--confirm-authorized`.

## Status

v1 in progress. Current step: scaffold (CLI parses arguments; no checks run yet).

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

Exit codes: `0` no findings at/above `--fail-on`, `1` findings at/above it, `2` scan error.
