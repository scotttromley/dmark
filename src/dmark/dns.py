"""DNS resolution and diagnostics for DMARC domain analysis."""

from __future__ import annotations

import re
import subprocess
from functools import lru_cache

try:
    import dns.resolver as _dns_resolver  # type: ignore
except Exception:
    _dns_resolver = None

try:
    import socket as _socket
except Exception:
    _socket = None


def _resolve_domain_dns_diagnostics(
    domain: str,
    observed_selectors: list[str],
) -> dict[str, object]:
    normalized_domain = (domain or "").strip().lower().strip(".")
    if not normalized_domain:
        return {
            "enabled": True,
            "domain": domain,
            "error": "Domain name is missing; DNS diagnostics not available.",
        }

    dmarc_host = f"_dmarc.{normalized_domain}"
    dmarc_txt_records = _lookup_txt_records(dmarc_host)
    dmarc_record = next(
        (
            value
            for value in dmarc_txt_records
            if value.lower().startswith("v=dmarc1")
        ),
        None,
    )
    root_txt_records = _lookup_txt_records(normalized_domain)
    spf_record = next(
        (
            value
            for value in root_txt_records
            if value.lower().startswith("v=spf1")
        ),
        None,
    )

    selector_candidates: list[str] = ["selector1", "selector2"]
    for selector in observed_selectors:
        cleaned = (selector or "").strip().lower()
        if not cleaned:
            continue
        if cleaned not in selector_candidates:
            selector_candidates.append(cleaned)

    selector_checks: dict[str, dict[str, object]] = {}
    for selector in selector_candidates[:8]:
        selector_host = f"{selector}._domainkey.{normalized_domain}"
        selector_cname = _lookup_cname_record(selector_host)
        selector_txt_records = _lookup_txt_records(selector_host) if not selector_cname else []
        dkim_txt = next(
            (
                value
                for value in selector_txt_records
                if value.lower().startswith("v=dkim1")
            ),
            None,
        )
        selector_checks[selector] = {
            "host": selector_host,
            "cname": selector_cname,
            "dkim_txt_record": dkim_txt,
            "dkim_txt_present": bool(dkim_txt),
            "m365_target": bool(
                selector_cname and ".onmicrosoft.com" in selector_cname.lower()
            ),
        }

    selector1 = selector_checks.get("selector1", {})
    selector2 = selector_checks.get("selector2", {})
    selector1_m365 = bool(selector1.get("m365_target"))
    selector2_m365 = bool(selector2.get("m365_target"))
    if selector1_m365 and selector2_m365:
        m365_dkim_status = "configured"
    elif selector1_m365 or selector2_m365:
        m365_dkim_status = "partial"
    else:
        m365_dkim_status = "not_detected"

    return {
        "enabled": True,
        "domain": normalized_domain,
        "dmarc_host": dmarc_host,
        "dmarc_record_found": bool(dmarc_record),
        "dmarc_record": dmarc_record,
        "spf_record_found": bool(spf_record),
        "spf_record": spf_record,
        "observed_selectors": selector_candidates,
        "dkim_selector_checks": selector_checks,
        "m365_dkim_status": m365_dkim_status,
    }


@lru_cache(maxsize=512)
def _lookup_txt_records(name: str) -> tuple[str, ...]:
    normalized_name = (name or "").strip().lower().strip(".")
    if not normalized_name:
        return ()

    if _dns_resolver is not None:
        try:
            resolver = _dns_resolver.Resolver()  # type: ignore[attr-defined]
            resolver.lifetime = 2.5
            resolver.timeout = 2.5
            answers = resolver.resolve(normalized_name, "TXT")
            values: list[str] = []
            for record in answers:
                text = record.to_text().strip()
                if text.startswith('"') and text.endswith('"'):
                    text = text[1:-1]
                text = text.replace('" "', "")
                if text:
                    values.append(text)
            return tuple(values)
        except Exception:
            pass

    return tuple(_lookup_txt_records_nslookup(normalized_name))


@lru_cache(maxsize=512)
def _lookup_cname_record(name: str) -> str | None:
    normalized_name = (name or "").strip().lower().strip(".")
    if not normalized_name:
        return None

    if _dns_resolver is not None:
        try:
            resolver = _dns_resolver.Resolver()  # type: ignore[attr-defined]
            resolver.lifetime = 2.5
            resolver.timeout = 2.5
            answers = resolver.resolve(normalized_name, "CNAME")
            for record in answers:
                target = str(getattr(record, "target", "")).strip()
                if target:
                    return target.rstrip(".")
        except Exception:
            pass

    return _lookup_cname_record_nslookup(normalized_name)


def _lookup_txt_records_nslookup(name: str) -> list[str]:
    output = _run_nslookup("TXT", name)
    if not output:
        return []
    # Windows nslookup typically prints TXT answers as:
    #   name    text =
    #       "value"
    # and may emit multiple quoted segments/records.
    values = [match.group(1).strip() for match in re.finditer(r'"([^"]+)"', output)]
    return [value for value in values if value]


def _lookup_cname_record_nslookup(name: str) -> str | None:
    output = _run_nslookup("CNAME", name)
    if not output:
        return None
    marker = "canonical name ="
    idx = output.lower().find(marker)
    if idx < 0:
        return None
    line = output[idx:].splitlines()[0]
    _, _, rhs = line.partition("=")
    value = rhs.strip().rstrip(".")
    return value or None


def _run_nslookup(record_type: str, name: str) -> str:
    try:
        completed = subprocess.run(
            ["nslookup", f"-type={record_type}", name],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except Exception:
        return ""
    return (completed.stdout or "") + "\n" + (completed.stderr or "")


def _reverse_dns(source_ip: str) -> str | None:
    try:
        import socket
        host, _, _ = socket.gethostbyaddr(source_ip)
        return host
    except Exception:
        return None
