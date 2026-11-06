import pytest

from wraith.scope import ScopeError, ScopeManager, parse_rule


@pytest.mark.parametrize(
    ("rules", "url", "expected"),
    [
        # exact host
        (["example.com"], "https://example.com/", True),
        (["example.com"], "http://example.com:8080/x?y=1", True),
        (["example.com"], "https://EXAMPLE.com./", True),
        (["example.com"], "https://www.example.com/", False),
        (["example.com"], "https://example.com.evil.net/", False),
        (["example.com"], "https://notexample.com/", False),
        # glob
        (["*.example.com"], "https://a.example.com/", True),
        (["*.example.com"], "https://a.b.example.com/", True),
        (["*.example.com"], "https://example.com/", False),
        (["*.example.com"], "https://example.com.evil.net/", False),
        (["example.com", "*.example.com"], "https://example.com/", True),
        # port pinning
        (["example.com:8443"], "https://example.com:8443/", True),
        (["example.com:8443"], "https://example.com/", False),
        (["example.com:443"], "https://example.com/", True),
        # URL-shaped rules
        (["https://example.com/app"], "http://example.com/other", True),
        # regex
        ([r"re:^api\d+\.example\.com$"], "https://api7.example.com/", True),
        ([r"re:^api\d+\.example\.com$"], "https://api.example.com/", False),
        # IPs
        (["10.0.0.5"], "http://10.0.0.5/", True),
        (["[::1]:8000"], "http://[::1]:8000/", True),
        # non-http schemes and junk are never in scope
        (["example.com"], "ftp://example.com/", False),
        (["example.com"], "file:///etc/passwd", False),
        (["example.com"], "not a url", False),
        # userinfo tricks resolve to the real host
        (["example.com"], "http://example.com@evil.net/", False),
        (["evil.net"], "http://example.com@evil.net/", True),
    ],
)
def test_is_in_scope(rules: list[str], url: str, expected: bool) -> None:
    assert ScopeManager(rules).is_in_scope(url) is expected


@pytest.mark.parametrize("rule", ["*", "*.*", "", "   ", "re:", "re:(", "host:99999", "host:abc"])
def test_rejects_invalid_or_too_broad_rules(rule: str) -> None:
    with pytest.raises(ScopeError):
        parse_rule(rule)


def test_requires_at_least_one_rule() -> None:
    with pytest.raises(ScopeError):
        ScopeManager([])


def test_check_records_blocked_urls() -> None:
    scope = ScopeManager(["example.com"])
    assert scope.check("https://example.com/")
    assert not scope.check("https://evil.net/")
    assert scope.blocked == {"https://evil.net/"}
