"""Source IP classification and Microsoft 365 detection."""

from __future__ import annotations

import ipaddress

_MICROSOFT365_OUTBOUND_CIDRS = (
    "40.92.0.0/15",
    "40.107.0.0/16",
    "52.100.0.0/14",
    "104.47.0.0/17",
    "2a01:111::/32",
)
_MICROSOFT365_OUTBOUND_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in _MICROSOFT365_OUTBOUND_CIDRS
)
_M365_ACTION_MIN_FAIL_MESSAGES = 10
_M365_HEAVY_MESSAGE_SHARE_THRESHOLD = 0.50


def _classify_source(
    source_ip: str,
    hostname: str | None,
) -> dict[str, str]:
    host = (hostname or "").strip().lower()

    relay_suffixes = (
        ".cloud-sec-av.com",
        ".iphmx.com",
        ".mimecast.com",
        ".proofpoint.com",
    )
    if host.endswith(relay_suffixes) or host in {
        "cloud-sec-av.com",
        "iphmx.com",
        "mimecast.com",
        "proofpoint.com",
    }:
        return {
            "category": "receiver_security_relay",
            "legit_status": "noise",
            "action": "ignore_for_scoring",
            "confidence": "high",
            "reason": (
                "Hostname matches recipient-side security/relay infrastructure "
                f"({host or source_ip})."
            ),
        }

    if host.endswith(".outbound.protection.outlook.com") or host.endswith(
        ".protection.outlook.com"
    ):
        return {
            "category": "esp_microsoft365_outbound",
            "legit_status": "approved",
            "action": "fix_alignment",
            "confidence": "high",
            "reason": (
                "Hostname matches Microsoft 365 outbound protection infrastructure."
            ),
        }

    if _is_microsoft365_outbound_ip(source_ip):
        return {
            "category": "esp_microsoft365_outbound",
            "legit_status": "approved",
            "action": "fix_alignment",
            "confidence": "medium",
            "reason": (
                "Source IP matches known Microsoft 365 outbound address patterns."
            ),
        }

    return {
        "category": "unknown",
        "legit_status": "pending_review",
        "action": "investigate",
        "confidence": "low",
        "reason": "No source classification rule matched.",
    }


def _is_microsoft365_outbound_ip(source_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address((source_ip or "").strip())
    except ValueError:
        return False

    for network in _MICROSOFT365_OUTBOUND_NETWORKS:
        if ip in network:
            return True
    return False


def _dynamic_auto_approve_min_volume(messages_total: int) -> int:
    if messages_total <= 0:
        return 100
    # Keep threshold strict for large domains, but scale down for smaller domains.
    dynamic_target = int(messages_total * 0.02)
    return max(10, min(100, dynamic_target))


def _select_m365_alignment_sender(
    source_fail_counts: dict[str, int],
    source_message_counts: dict[str, int],
    classified_sources: dict[str, dict[str, str]],
) -> dict[str, object] | None:
    candidates: list[tuple[str, int, int]] = []
    total_m365_failures = 0
    for source_ip, fail_count in source_fail_counts.items():
        if fail_count <= 0:
            continue
        classification = classified_sources.get(source_ip, {})
        if classification.get("category") != "esp_microsoft365_outbound":
            continue
        total_messages = source_message_counts.get(source_ip, 0)
        candidates.append((source_ip, fail_count, total_messages))
        total_m365_failures += fail_count
    if not candidates or total_m365_failures < _M365_ACTION_MIN_FAIL_MESSAGES:
        return None
    source_ip, fail_count, total_messages = sorted(
        candidates,
        key=lambda item: item[1],
        reverse=True,
    )[0]
    return {
        "source_ip": source_ip,
        "dmarc_fail_count": fail_count,
        "dmarc_fail_count_total_m365": total_m365_failures,
        "message_count": total_messages,
        "classification": "esp_microsoft365_outbound",
        "suggested_action": "fix_alignment",
    }


def _is_m365_dkim_carrying_load(
    *,
    has_m365_senders: bool,
    dns_diagnostics: dict[str, object],
    dkim_aligned_rate: float,
    spf_alignment_gap_rate: float,
    legitimate_fail_rate: float,
) -> bool:
    if not has_m365_senders:
        return False
    if str(dns_diagnostics.get("m365_dkim_status", "")) != "configured":
        return False
    if dkim_aligned_rate < 0.90:
        return False
    if spf_alignment_gap_rate < 0.05:
        return False
    if legitimate_fail_rate > 0.02:
        return False
    return True
