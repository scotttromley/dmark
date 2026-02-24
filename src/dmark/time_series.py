"""Time series construction and helper utilities for DMARC analysis output."""

from __future__ import annotations


def _top_items(
    counts: dict[str, int],
    limit: int,
    value_key: str,
) -> list[dict[str, object]]:
    items = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:max(0, limit)]
    return [
        {"name": key, value_key: value}
        for key, value in items
    ]


def _top_items_for_source(
    counts_by_source: dict[str, dict[str, int]],
    source_ip: str,
    limit: int = 3,
) -> list[dict[str, object]]:
    nested = counts_by_source.get(source_ip, {})
    if not nested:
        return []
    return _top_items(nested, limit=limit, value_key="message_count")


def _sum_day_counts_for_sources(
    source_day_counts: dict[str, dict[str, int]],
    source_ips: set[str],
) -> dict[str, int]:
    if not source_ips:
        return {}
    totals: dict[str, int] = {}
    for source_ip in source_ips:
        day_counts = source_day_counts.get(source_ip, {})
        for day, count in day_counts.items():
            totals[day] = totals.get(day, 0) + int(count)
    return totals


def _legitimate_day_basis_counts(
    basis: str,
    messages_by_day: dict[str, int],
    dmarc_fail_by_day: dict[str, int],
    noise_messages_by_day: dict[str, int],
    noise_fail_by_day: dict[str, int],
    approved_messages_by_day: dict[str, int],
    approved_fail_by_day: dict[str, int],
) -> tuple[dict[str, int], dict[str, int]]:
    if basis == "approved_and_auto_approved_non_noise_senders":
        return dict(approved_messages_by_day), dict(approved_fail_by_day)

    if basis in {
        "all_observed_non_noise_traffic",
        "all_observed_non_noise_traffic_no_approved_sender_matches",
    }:
        messages: dict[str, int] = {}
        fails: dict[str, int] = {}
        for day, total in messages_by_day.items():
            noise_messages = int(noise_messages_by_day.get(day, 0))
            messages[day] = max(0, int(total) - noise_messages)
        for day, total_fail in dmarc_fail_by_day.items():
            noise_fail = int(noise_fail_by_day.get(day, 0))
            fails[day] = max(0, int(total_fail) - noise_fail)
        return messages, fails

    return dict(messages_by_day), dict(dmarc_fail_by_day)


def _build_daily_time_series(
    messages_by_day: dict[str, int],
    dmarc_pass_by_day: dict[str, int],
    dmarc_fail_by_day: dict[str, int],
    dkim_aligned_pass_by_day: dict[str, int],
    spf_aligned_pass_by_day: dict[str, int],
    approved_messages_by_day: dict[str, int] | None = None,
    noise_messages_by_day: dict[str, int] | None = None,
    approved_fail_by_day: dict[str, int] | None = None,
    noise_fail_by_day: dict[str, int] | None = None,
    legitimate_basis_messages_by_day: dict[str, int] | None = None,
    legitimate_basis_fail_by_day: dict[str, int] | None = None,
) -> list[dict[str, object]]:
    approved_messages_by_day = approved_messages_by_day or {}
    noise_messages_by_day = noise_messages_by_day or {}
    approved_fail_by_day = approved_fail_by_day or {}
    noise_fail_by_day = noise_fail_by_day or {}
    legitimate_basis_messages_by_day = legitimate_basis_messages_by_day or approved_messages_by_day
    legitimate_basis_fail_by_day = legitimate_basis_fail_by_day or approved_fail_by_day
    if not messages_by_day:
        return []

    rows: list[dict[str, object]] = []
    for day in sorted(messages_by_day.keys()):
        total = int(messages_by_day.get(day, 0))
        if total <= 0:
            continue
        dmarc_pass = int(dmarc_pass_by_day.get(day, 0))
        dmarc_fail = int(dmarc_fail_by_day.get(day, 0))
        dkim_aligned = int(dkim_aligned_pass_by_day.get(day, 0))
        spf_aligned = int(spf_aligned_pass_by_day.get(day, 0))
        approved_messages = int(approved_messages_by_day.get(day, 0))
        noise_messages = int(noise_messages_by_day.get(day, 0))
        pending_messages = max(0, total - approved_messages - noise_messages)
        approved_fail = int(approved_fail_by_day.get(day, 0))
        legitimate_messages = int(legitimate_basis_messages_by_day.get(day, 0))
        legitimate_fail = int(legitimate_basis_fail_by_day.get(day, 0))
        noise_fail = int(noise_fail_by_day.get(day, 0))
        attack_fail = max(0, dmarc_fail - approved_fail - noise_fail)
        non_noise_messages = max(0, total - noise_messages)
        rows.append(
            {
                "date": day,
                "messages_total": total,
                "dmarc_pass_count": dmarc_pass,
                "dmarc_fail_count": dmarc_fail,
                "dmarc_fail_rate": round((dmarc_fail / total) if total > 0 else 0.0, 6),
                "dkim_aligned_pass_rate": round(
                    (dkim_aligned / total) if total > 0 else 0.0,
                    6,
                ),
                "spf_aligned_pass_rate": round(
                    (spf_aligned / total) if total > 0 else 0.0,
                    6,
                ),
                "approved_messages": approved_messages,
                "noise_messages": noise_messages,
                "pending_review_messages": pending_messages,
                "legitimate_basis_messages": legitimate_messages,
                "legitimate_fail_count": legitimate_fail,
                "attack_pressure_fail_count": attack_fail,
                "legitimate_fail_rate": round(
                    (legitimate_fail / legitimate_messages) if legitimate_messages > 0 else 0.0,
                    6,
                ),
                "attack_pressure_fail_rate": round(
                    (attack_fail / non_noise_messages) if non_noise_messages > 0 else 0.0,
                    6,
                ),
            }
        )
    return rows


def _source_dkim_failure_mode(
    source_ip: str,
    missing_dkim_counts: dict[str, int],
    dkim_auth_fail_counts: dict[str, int],
    dkim_unaligned_counts: dict[str, int],
) -> str:
    missing = missing_dkim_counts.get(source_ip, 0)
    auth_fail = dkim_auth_fail_counts.get(source_ip, 0)
    unaligned = dkim_unaligned_counts.get(source_ip, 0)
    if missing >= auth_fail and missing >= unaligned and missing > 0:
        return "dkim_missing"
    if auth_fail >= missing and auth_fail >= unaligned and auth_fail > 0:
        return "dkim_auth_fail"
    if unaligned > 0:
        return "dkim_pass_unaligned"
    return "unknown"


def _legitimate_dkim_failure_modes(
    source_ips: set[str],
    missing_dkim_counts: dict[str, int],
    dkim_auth_fail_counts: dict[str, int],
    dkim_unaligned_counts: dict[str, int],
) -> dict[str, int]:
    return {
        "dkim_missing": sum(missing_dkim_counts.get(source_ip, 0) for source_ip in source_ips),
        "dkim_auth_fail": sum(dkim_auth_fail_counts.get(source_ip, 0) for source_ip in source_ips),
        "dkim_pass_unaligned": sum(dkim_unaligned_counts.get(source_ip, 0) for source_ip in source_ips),
    }
