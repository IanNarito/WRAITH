from pathlib import Path

import pytest

from wraith.config import ConfigError, OutputFormat, build_config, load_config_file
from wraith.models import Severity


def test_build_config_defaults_scope_to_target_host() -> None:
    config = build_config({"target": "example.com"})
    assert config.target == "https://example.com"
    assert config.scope == ("example.com",)
    assert config.safe_mode is True
    assert config.confirm_authorized is False


def test_build_config_parses_values() -> None:
    config = build_config(
        {
            "target": "http://t.test/",
            "scope": "t.test, *.t.test",
            "checks": ["cors", "cookies,tls_config"],
            "output_format": "JSON",
            "fail_on": "Medium",
            "header": ["X-A: 1"],
            "cookie": ["a=1; b=2"],
        }
    )
    assert config.scope == ("t.test", "*.t.test")
    assert config.checks == ("cors", "cookies", "tls_config")
    assert config.output_format is OutputFormat.JSON
    assert config.fail_on is Severity.MEDIUM
    assert config.headers == {"X-A": "1"}
    assert config.cookies == {"a": "1", "b": "2"}


@pytest.mark.parametrize(
    "values",
    [
        {"target": "ftp://x"},
        {"target": "x.test", "scope": "*"},
        {"target": "x.test", "rate": 0},
        {"target": "x.test", "concurrency": "many"},
        {"target": "x.test", "safe_mode": "no"},
        {"target": "x.test", "fail_on": "urgent"},
        {"target": "x.test", "proxy": "socks9://x"},
        {"target": "x.test", "header": ["no-colon"]},
    ],
)
def test_build_config_rejects_bad_values(values: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        build_config(values)


def test_load_config_file(tmp_path: Path) -> None:
    path = tmp_path / "wraith.yaml"
    path.write_text(
        "scope: [t.test]\nrate: 2\nformat: html\nheaders:\n  X-A: '1'\ncookies:\n  s: abc\n",
        encoding="utf-8",
    )
    values = load_config_file(path)
    assert values == {
        "scope": ["t.test"],
        "rate": 2,
        "output_format": "html",
        "header": ["X-A: 1"],
        "cookie": ["s=abc"],
    }


@pytest.mark.parametrize(
    "body", ["target: x.test\n", "confirm_authorized: true\n", "nope: 1\n", "- a\n"]
)
def test_load_config_file_rejects_disallowed_keys(tmp_path: Path, body: str) -> None:
    path = tmp_path / "wraith.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config_file(path)
