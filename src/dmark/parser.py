from __future__ import annotations

import gzip
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import AuthResult, DmarcRecord, DmarcReport

_KNOWN_OVERRIDE_REASONS = {
    "forwarded",
    "sampled_out",
    "trusted_forwarder",
    "mailing_list",
    "local_policy",
    "other",
}


class ParseError(RuntimeError):
    pass


def parse_report_file(path: Path) -> DmarcReport:
    return parse_report_bytes(path.read_bytes(), source_name=str(path))


def parse_report_bytes(raw: bytes, source_name: str = "<memory>") -> DmarcReport:
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            raise ParseError(f"Failed to decompress gzip content in {source_name}") from exc
    return parse_report_xml(raw, source_name=source_name)


def parse_report_xml(raw_xml: bytes, source_name: str = "<memory>") -> DmarcReport:
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        raise ParseError(f"Invalid XML in {source_name}: {exc}") from exc

    # Most DMARC reports are namespace-free. When namespaces are present, strip
    # them so we can use stable XPath lookups.
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]

    org_name = _find_text(root, "./report_metadata/org_name", default="unknown")
    report_id = _find_text(root, "./report_metadata/report_id", default="")
    date_begin = _find_int(root, "./report_metadata/date_range/begin", default=0)
    date_end = _find_int(root, "./report_metadata/date_range/end", default=0)

    policy_domain = _find_text(root, "./policy_published/domain", default="")
    adkim = _find_text(root, "./policy_published/adkim", default="r").lower()
    aspf = _find_text(root, "./policy_published/aspf", default="r").lower()
    policy_p = _find_text(root, "./policy_published/p", default="none").lower()
    policy_sp = _find_text(root, "./policy_published/sp", default=policy_p).lower()
    policy_pct = _find_int(root, "./policy_published/pct", default=100)

    records: list[DmarcRecord] = []
    for record_node in root.findall("./record"):
        source_ip = _find_text(record_node, "./row/source_ip", default="unknown")
        count = _find_int(record_node, "./row/count", default=0)
        disposition = _find_text(
            record_node,
            "./row/policy_evaluated/disposition",
            default="none",
        ).lower()
        header_from = _find_text(
            record_node,
            "./identifiers/header_from",
            default=policy_domain,
        ).lower()
        envelope_from = _find_text(
            record_node,
            "./identifiers/envelope_from",
            default="",
        ).lower()
        override_reasons = tuple(
            _normalize_override_reason(
                _find_text(reason_node, "./type", default="other")
            )
            for reason_node in record_node.findall("./row/policy_evaluated/reason")
        )

        dkim_results: list[AuthResult] = []
        for node in record_node.findall("./auth_results/dkim"):
            dkim_results.append(
                AuthResult(
                    domain=_find_text(node, "./domain", default="").lower(),
                    result=_find_text(node, "./result", default="").lower(),
                    selector=_find_text(node, "./selector", default="").lower(),
                )
            )

        spf_results: list[AuthResult] = []
        for node in record_node.findall("./auth_results/spf"):
            spf_results.append(
                AuthResult(
                    domain=_find_text(node, "./domain", default="").lower(),
                    result=_find_text(node, "./result", default="").lower(),
                )
            )

        records.append(
            DmarcRecord(
                source_ip=source_ip,
                count=max(0, count),
                disposition=disposition,
                header_from=header_from,
                envelope_from=envelope_from,
                override_reasons=override_reasons,
                dkim_results=tuple(dkim_results),
                spf_results=tuple(spf_results),
            )
        )

    return DmarcReport(
        source_name=source_name,
        org_name=org_name,
        report_id=report_id,
        date_begin=date_begin,
        date_end=date_end,
        policy_domain=policy_domain.lower(),
        adkim=adkim if adkim in {"r", "s"} else "r",
        aspf=aspf if aspf in {"r", "s"} else "r",
        policy_p=policy_p,
        policy_sp=policy_sp,
        policy_pct=max(0, min(policy_pct, 100)),
        records=tuple(records),
    )


def _find_text(node: ET.Element, xpath: str, default: str) -> str:
    target = node.find(xpath)
    if target is None or target.text is None:
        return default
    value = target.text.strip()
    return value if value else default


def _find_int(node: ET.Element, xpath: str, default: int) -> int:
    raw = _find_text(node, xpath, default=str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def _normalize_override_reason(raw_value: str) -> str:
    value = (raw_value or "").strip().lower()
    if value in _KNOWN_OVERRIDE_REASONS:
        return value
    return "other"
