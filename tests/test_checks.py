import pytest
from pytest_httpserver import HTTPServer

from tests.conftest import ConfigFactory, make_page
from wraith.checks.security_headers import csp_weaknesses, evaluate
from wraith.context import Page
from wraith.engine import Engine
from wraith.models import Confidence, Severity

GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def titles(page: Page) -> set[str]:
    return {f.title for f in evaluate(page)}


# --- security_headers: unit tests on evaluate() -------------------------------------------------


def test_hardened_page_has_no_findings() -> None:
    assert evaluate(make_page(GOOD_HEADERS)) == []


def test_bare_page_reports_every_missing_header() -> None:
    findings = evaluate(make_page({}))
    assert {f.title for f in findings} == {
        "Missing Content-Security-Policy",
        "Missing Strict-Transport-Security",
        "Missing clickjacking protection",
        "Missing X-Content-Type-Options",
        "Missing Referrer-Policy",
        "Missing Permissions-Policy",
    }
    for finding in findings:
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.evidence and finding.evidence[0].request.startswith("GET / HTTP/1.1")


def test_hsts_not_expected_over_plain_http() -> None:
    assert "Missing Strict-Transport-Security" not in titles(make_page({}, url="http://app.test/"))


def test_non_html_responses_skip_document_only_headers() -> None:
    found = titles(make_page({}, content_type="application/json", body="{}"))
    assert found == {"Missing Strict-Transport-Security", "Missing X-Content-Type-Options"}


@pytest.mark.parametrize(
    ("hsts", "title"),
    [
        ("max-age=0", "Weak Strict-Transport-Security"),
        ("max-age=86400", "Weak Strict-Transport-Security"),
        ("includeSubDomains", "Invalid Strict-Transport-Security"),
    ],
)
def test_weak_hsts(hsts: str, title: str) -> None:
    assert title in titles(make_page({**GOOD_HEADERS, "Strict-Transport-Security": hsts}))


def test_weak_csp_is_low_and_carries_policy_as_evidence() -> None:
    policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    findings = evaluate(make_page({**GOOD_HEADERS, "Content-Security-Policy": policy}))
    assert [(f.title, f.severity) for f in findings] == [
        ("Weak Content-Security-Policy", Severity.LOW)
    ]
    assert findings[0].evidence[0].matched == policy


@pytest.mark.parametrize(
    ("policy", "weak"),
    [
        ("default-src 'self'", False),
        ("script-src 'self' 'unsafe-inline' 'nonce-abc'", False),  # nonce disables unsafe-inline
        ("script-src 'strict-dynamic' 'nonce-abc' https:", False),
        ("script-src 'self' 'unsafe-eval'", True),
        ("script-src *", True),
        ("img-src 'self'", True),  # nothing restricts scripts
    ],
)
def test_csp_weaknesses(policy: str, weak: bool) -> None:
    assert bool(csp_weaknesses(policy)) is weak


def test_meta_csp_counts_but_not_for_frame_ancestors() -> None:
    headers = {k: v for k, v in GOOD_HEADERS.items() if k != "Content-Security-Policy"}
    body = (
        '<html><head><meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'self'; frame-ancestors 'none'\"></head></html>"
    )
    found = titles(make_page(headers, body=body))
    assert "Missing Content-Security-Policy" not in found
    assert "Missing clickjacking protection" in found  # frame-ancestors is ignored in <meta>


def test_x_frame_options_satisfies_clickjacking_and_allow_from_does_not() -> None:
    no_fa = {**GOOD_HEADERS, "Content-Security-Policy": "default-src 'self'"}
    assert titles(make_page({**no_fa, "X-Frame-Options": "SAMEORIGIN"})) == set()
    assert titles(make_page({**no_fa, "X-Frame-Options": "ALLOW-FROM https://x"})) == {
        "Invalid X-Frame-Options"
    }


def test_weak_referrer_policy_uses_last_known_value() -> None:
    weak = {**GOOD_HEADERS, "Referrer-Policy": "no-referrer, unsafe-url"}
    assert titles(make_page(weak)) == {"Weak Referrer-Policy"}
    fine = {**GOOD_HEADERS, "Referrer-Policy": "unsafe-url, no-referrer, made-up"}
    assert titles(make_page(fine)) == set()


def test_error_pages_downgrade_confidence() -> None:
    findings = evaluate(make_page({}, status=403))
    assert findings and all(f.confidence is Confidence.PROBABLE for f in findings)


# --- security_headers: end to end through the engine against a local server ---------------------


async def test_engine_runs_security_headers_against_fixture_server(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<html><body>hello</body></html>",
        content_type="text/html",
        headers={"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"},
    )
    result = await Engine(make_config(checks=("security_headers",))).run()

    assert result.failures == ()
    assert result.checks_run == ("security_headers",)
    assert [f.title for f in result.findings] == [
        "Missing Content-Security-Policy",  # MEDIUM sorts first
        "Missing Permissions-Policy",
        "Missing Referrer-Policy",
    ]
    assert result.exit_code(Severity.MEDIUM) == 1
    assert result.exit_code(Severity.HIGH) == 0
