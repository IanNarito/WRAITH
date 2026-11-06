"""TLS/SSL configuration: certificate validity, legacy protocols, weak ciphers, plain HTTP.

Handshakes use Python's ``ssl`` module and go through ``HTTPClient.raw_slot`` so they stay
inside scope and the rate limit. A probe that cannot run (e.g. the local OpenSSL refuses TLS
1.0) yields no finding: a missed finding is preferred over a false one.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
import warnings
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient
from wraith.models import Confidence, Evidence, Finding, Severity

logger = logging.getLogger("wraith.checks.tls")

EXPIRY_WARNING_DAYS = 30
WEAK_CIPHERS = "RC4:3DES:DES:NULL:EXPORT:aNULL:eNULL:MD5:@SECLEVEL=0"
REFERENCES = (
    "https://wiki.mozilla.org/Security/Server_Side_TLS",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
)
# OpenSSL X509 verify codes
_EXPIRED, _NOT_YET_VALID = 10, 9
_SELF_SIGNED, _SELF_SIGNED_IN_CHAIN = 18, 19
_NO_ISSUER, _NO_ISSUER_LEAF = 20, 21
_HOSTNAME_MISMATCH = 62


@dataclass(frozen=True)
class Handshake:
    version: str | None
    cipher: str | None
    cert: dict[str, Any]


class TLSConfigCheck(BaseCheck):
    name = "tls_config"
    severity_hint = Severity.MEDIUM
    description = "Certificate validity, TLS < 1.2, weak ciphers, and unencrypted HTTP"

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        url = httpx.URL(ctx.base_url)
        if url.scheme != "https":
            yield _plain_http_finding(ctx)
            return
        host, port = url.host, url.port or 443

        # 1. Default, verifying handshake: certificate problems and expiry.
        try:
            hs = await _handshake(http, host, port, ssl.create_default_context())
        except ssl.SSLCertVerificationError as exc:
            yield _cert_error_finding(ctx.base_url, host, port, exc)
        else:
            if (finding := _expiry_finding(ctx.base_url, host, port, hs, time.time())) is not None:
                yield finding

        # 2. Legacy protocol support.
        for version, label in (
            (ssl.TLSVersion.TLSv1, "TLS 1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        ):
            context = _pinned_context(version)
            if context is None:
                logger.info("local OpenSSL cannot offer %s; skipping that probe", label)
                continue
            legacy = await _try_handshake(http, host, port, context)
            if legacy is not None:
                yield _legacy_finding(ctx.base_url, host, port, label, legacy)

        # 3. Weak cipher suites (TLS <= 1.2; TLS 1.3 suites are all strong).
        context = _weak_cipher_context()
        if context is None:
            logger.info("local OpenSSL has no weak ciphers to offer; skipping weak-cipher probe")
        else:
            weak = await _try_handshake(http, host, port, context)
            if weak is not None and weak.cipher:
                yield _weak_cipher_finding(ctx.base_url, host, port, weak)


async def _handshake(http: HTTPClient, host: str, port: int, context: ssl.SSLContext) -> Handshake:
    async with http.raw_slot(host, port):
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=http.timeout,
        )
        try:
            ssl_object: ssl.SSLObject = writer.get_extra_info("ssl_object")
            cipher = ssl_object.cipher()
            return Handshake(
                version=ssl_object.version(),
                cipher=cipher[0] if cipher else None,
                cert=dict(ssl_object.getpeercert() or {}),
            )
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def _try_handshake(
    http: HTTPClient, host: str, port: int, context: ssl.SSLContext
) -> Handshake | None:
    """A handshake that is expected to fail on a well-configured server."""
    try:
        return await _handshake(http, host, port, context)
    except (TimeoutError, ssl.SSLError, OSError) as exc:
        logger.debug("probe handshake to %s:%d refused: %s", host, port, exc)
        return None


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _pinned_context(version: ssl.TLSVersion) -> ssl.SSLContext | None:
    try:
        context = _unverified_context()
        with warnings.catch_warnings():  # offering a deprecated protocol is the point here
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        context.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return context


def _weak_cipher_context() -> ssl.SSLContext | None:
    try:
        context = _unverified_context()
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(WEAK_CIPHERS)
    except (ValueError, ssl.SSLError):
        return None
    return context


def _evidence(host: str, port: int, probe: str, result: str, matched: str | None) -> Evidence:
    return Evidence(
        request=f"TLS handshake to {host}:{port} (SNI {host}) - {probe}",
        response_snippet=result,
        matched=matched,
    )


def _describe(hs: Handshake) -> str:
    lines = [f"negotiated protocol: {hs.version}", f"negotiated cipher: {hs.cipher}"]
    if hs.cert:
        lines.append(f"certificate notAfter: {hs.cert.get('notAfter')}")
    return "\n".join(lines)


def _finding(
    url: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    evidence: Evidence,
    confidence: Confidence = Confidence.CONFIRMED,
) -> Finding:
    return Finding(
        check=TLSConfigCheck.name,
        title=title,
        url=url,
        severity=severity,
        confidence=confidence,
        description=description,
        remediation=remediation,
        evidence=(evidence,),
        references=REFERENCES,
    )


def _cert_error_finding(
    url: str, host: str, port: int, exc: ssl.SSLCertVerificationError
) -> Finding:
    code, message = exc.verify_code, exc.verify_message or str(exc)
    confidence = Confidence.CONFIRMED
    if code == _EXPIRED:
        title, detail = "Expired TLS certificate", "The certificate has expired."
    elif code == _NOT_YET_VALID:
        title, detail = "TLS certificate not yet valid", "The certificate's validity starts later."
    elif code in (_SELF_SIGNED, _SELF_SIGNED_IN_CHAIN):
        title, detail = (
            "Self-signed TLS certificate",
            "The certificate chain ends in a self-signed certificate no public CA vouches for.",
        )
    elif code == _HOSTNAME_MISMATCH:
        title, detail = (
            "TLS certificate hostname mismatch",
            f"The certificate is not valid for {host}.",
        )
    elif code in (_NO_ISSUER, _NO_ISSUER_LEAF):
        title = "Untrusted TLS certificate chain"
        detail = (
            "The issuer could not be verified: either the server omits intermediate "
            "certificates or the CA is not publicly trusted (it may be an internal CA)."
        )
        confidence = Confidence.PROBABLE
    else:
        title, detail = "Invalid TLS certificate", "Certificate verification failed."
    return _finding(
        url,
        title,
        Severity.MEDIUM,
        f"{detail} Browsers show a security warning, and users who click through can be "
        "intercepted by anyone able to present their own certificate.",
        "Install a certificate from a trusted CA that covers this hostname, serve the full "
        "intermediate chain, and automate renewal (e.g. ACME / Let's Encrypt).",
        _evidence(
            host,
            port,
            "default verifying client",
            f"verification failed (code {code}): {message}",
            message,
        ),
        confidence,
    )


def _expiry_finding(url: str, host: str, port: int, hs: Handshake, now: float) -> Finding | None:
    not_after = hs.cert.get("notAfter")
    if not not_after:
        return None
    days_left = int((ssl.cert_time_to_seconds(str(not_after)) - now) // 86400)
    if days_left >= EXPIRY_WARNING_DAYS:
        return None
    return _finding(
        url,
        "TLS certificate expires soon",
        Severity.LOW,
        f"The certificate expires in {days_left} day(s) ({not_after}). After that, browsers "
        "will reject the connection.",
        "Renew the certificate and automate renewal.",
        _evidence(host, port, "default verifying client", _describe(hs), str(not_after)),
    )


def _legacy_finding(url: str, host: str, port: int, label: str, hs: Handshake) -> Finding:
    return _finding(
        url,
        f"Deprecated protocol {label} supported",
        Severity.MEDIUM,
        f"The server completed a handshake restricted to {label}. {label} is deprecated "
        "(RFC 8996) and lacks modern protections; it enables downgrade attacks.",
        "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and TLS 1.3.",
        _evidence(host, port, f"client offering only {label}", _describe(hs), hs.version),
    )


def _weak_cipher_finding(url: str, host: str, port: int, hs: Handshake) -> Finding:
    return _finding(
        url,
        "Weak TLS cipher suite accepted",
        Severity.MEDIUM,
        f"The server accepted the weak cipher suite {hs.cipher} when the client offered only "
        "weak suites (RC4, 3DES, DES, NULL, EXPORT, anonymous, or MD5-based).",
        "Restrict the server to AEAD suites (AES-GCM, ChaCha20-Poly1305) with forward secrecy; "
        "see the Mozilla 'intermediate' configuration.",
        _evidence(host, port, "client offering only weak ciphers", _describe(hs), hs.cipher),
    )


def _plain_http_finding(ctx: ScanContext) -> Finding:
    return _finding(
        ctx.base_url,
        "Site served over unencrypted HTTP",
        Severity.MEDIUM,
        "The target was served over plain HTTP without redirecting to HTTPS, so all traffic, "
        "including credentials and session cookies, can be read and modified on the network.",
        "Serve the site over HTTPS only, redirect HTTP to HTTPS, and enable HSTS.",
        ctx.base.exchange.to_evidence(include_body=False),
    )
