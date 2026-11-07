"""Insecure direct object reference (IDOR) candidate detection (aggressive, opt-in, OFF by default).

True object-level authorization testing needs two identities to compare; a single-session scanner
can only surface *candidates*. This check does that conservatively and only when enabled with
``--checks idor``. For a GET parameter that looks like an object id (an integer value, or a name
like ``id``/``user``/``order``), it requests the neighbouring ids and reports only when:

* the neighbour returns 200 with a body the same size as the baseline (same template) but
  different content (a different record), and
* an absurd, almost-certainly-invalid id returns a markedly different response - proving the
  endpoint actually distinguishes real records from missing ones (so it is not a static page that
  ignores the id).

Every request is a plain GET through the rate-limited client; nothing is modified. Findings are
PROBABLE and mean "this reference is enumerable" - confirm a real authorization flaw by requesting
another user's object from a second, lower-privileged account.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.injection import MAX_POINTS, InjectionPoint, points_from_context, send_probe
from wraith.models import Confidence, Finding, Severity

REFERENCES = (
    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/639.html",
)
# Parameter names that commonly carry a direct object reference.
ID_PARAM_HINTS = frozenset(
    {
        "id", "uid", "userid", "user_id", "user", "account", "accountid", "account_id", "acct",
        "order", "orderid", "order_id", "doc", "docid", "document", "file", "fileid", "file_id",
        "pid", "num", "number", "record", "recordid", "rid", "item", "itemid", "invoice", "msg",
        "message", "messageid", "ticket", "ticketid", "object", "objectid", "oid", "seq", "row",
        "profile", "profileid", "report", "reportid", "customer", "customerid",
    }
)
MIN_BODY = 64  # ignore tiny bodies; too little structure to compare meaningfully
_SIZE_BAND = 0.15  # neighbour body must be within +/-15% of baseline to count as "same template"
_CONTROL_OFFSET = 1_000_003  # an id unlikely to exist, to probe the "not found" response


def _id_like(point: InjectionPoint) -> bool:
    if point.method != "GET" or point.source != "query":
        return False
    return point.param.lower() in ID_PARAM_HINTS or point.baseline().strip().isdigit()


class IdorCheck(BaseCheck):
    name = "idor"
    severity_hint = Severity.HIGH
    description = "Enumerable direct object references (IDOR candidates); opt-in, off by default"
    enabled_by_default = False
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        points = [p for p in points_from_context(ctx) if _id_like(p)]
        for point in points[:MAX_POINTS]:
            finding = await _probe(http, point)
            if finding is not None:
                yield finding


async def _probe(http: HTTPClient, point: InjectionPoint) -> Finding | None:
    raw = point.baseline().strip()
    if not raw.isdigit():
        return None  # need a numeric reference to enumerate neighbours safely
    value = int(raw)

    baseline = await _get(http, point, raw)
    if baseline is None or baseline.status_code != 200 or len(baseline.text) < MIN_BODY:
        return None
    base_len = len(baseline.text)

    # The endpoint must distinguish a real record from a missing one, or the id is simply ignored.
    control = await _get(http, point, str(value + _CONTROL_OFFSET))
    if control is None or not _control_distinct(baseline, control):
        return None

    neighbours = [str(value + 1)] + ([str(value - 1)] if value > 1 else [])
    for candidate in neighbours:
        response = await _get(http, point, candidate)
        if response is None or response.status_code != 200:
            continue
        same_template = abs(len(response.text) - base_len) <= _SIZE_BAND * base_len
        different_record = response.text != baseline.text
        distinct_from_control = _control_distinct(response, control)
        if same_template and different_record and distinct_from_control:
            return _finding(point, raw, candidate, response)
    return None


async def _get(http: HTTPClient, point: InjectionPoint, value: str) -> Response | None:
    try:
        return await send_probe(http, point, value)
    except HTTPClientError:
        return None


def _control_distinct(record: Response, control: Response) -> bool:
    """True if ``control`` looks like a different (e.g. not-found) response than ``record``."""
    if control.status_code != record.status_code:
        return True
    return abs(len(control.text) - len(record.text)) > _SIZE_BAND * max(len(record.text), 1)


def _finding(point: InjectionPoint, base_value: str, neighbour: str, response: Response) -> Finding:
    return Finding(
        check=IdorCheck.name,
        title=f"Enumerable object reference in parameter {point.param!r}",
        url=point.action,
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description=(
            f"Changing the {point.source} parameter {point.param!r} from {base_value!r} to "
            f"{neighbour!r} returned a different record of the same shape, while an out-of-range "
            "id returned a clearly different response. The identifier is a direct object reference "
            "that can be enumerated. If the application does not check that the current user owns "
            "the requested object, this is an insecure direct object reference exposing other "
            "users' data. Confirm by requesting one account's object while logged in as another."
        ),
        remediation=(
            "Enforce object-level authorization on every request: verify the authenticated user is "
            "allowed to access the specific object, not merely that they are logged in. Prefer "
            "unpredictable identifiers (UUIDs) as defense in depth, but never rely on them alone."
        ),
        evidence=(response.exchange.to_evidence(None),),
        references=REFERENCES,
    )
