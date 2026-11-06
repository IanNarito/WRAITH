import pytest

from wraith.checks.security_headers import SecurityHeadersCheck
from wraith.registry import PluginRegistry, RegistryError


def test_discovers_checks_in_package() -> None:
    checks = PluginRegistry().checks
    assert checks["security_headers"] is SecurityHeadersCheck
    assert "base" not in checks


def test_select_defaults_include_and_exclude() -> None:
    registry = PluginRegistry()
    # Safe mode (the default) runs enabled-by-default checks that are not aggressive.
    assert [c.name for c in registry.select()] == [
        n for n, c in registry.checks.items() if c.enabled_by_default and not c.requires_aggressive
    ]
    # Aggressive mode adds the aggressive checks.
    assert set(c.name for c in registry.select(safe_mode=False)) >= {"sqli", "xss_reflected"}
    assert [c.name for c in registry.select(["security_headers"])] == ["security_headers"]
    assert registry.select(["security_headers"], ["security_headers"]) == []


def test_unknown_check_names_are_rejected() -> None:
    with pytest.raises(RegistryError, match="unknown check"):
        PluginRegistry().select(["nope"])
    with pytest.raises(RegistryError, match="unknown check"):
        PluginRegistry().select(exclude=["nope"])
