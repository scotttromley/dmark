from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from .models import DmarcReport, DomainSummary

ProgressCallback = Callable[[dict[str, object]], None]


def analyze_reports(
    reports: list[DmarcReport],
    min_fail_rate_alert: float = 0.02,
    min_messages_alert: int = 100,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, DomainSummary]:
    summary_by_domain: dict[str, DomainSummary] = {}
    total_reports = len(reports)
    normalized_domain_cache: dict[str, str] = {}

    for index, report in enumerate(reports, start=1):
        domain = report.policy_domain or "unknown"
        if domain not in summary_by_domain:
            summary_by_domain[domain] = DomainSummary(domain=domain)
        summary = summary_by_domain[domain]
        report_day = _report_day_key(report)
        summary.reports_seen += 1
        summary.policy_counts[report.policy_p] = summary.policy_counts.get(report.policy_p, 0) + 1
        summary.policy_pct_total += max(0, min(int(report.policy_pct), 100))
        summary.policy_pct_reports += 1
        reporter = (report.org_name or "unknown").strip() or "unknown"
        summary.reporter_counts[reporter] = summary.reporter_counts.get(reporter, 0) + 1

        for record in report.records:
            count = record.count
            if count <= 0:
                continue

            header_from = _normalize_domain_cached(record.header_from, normalized_domain_cache)
            if not header_from:
                header_from = _normalize_domain_cached(report.policy_domain, normalized_domain_cache)
            envelope_from = _normalize_domain_cached(record.envelope_from, normalized_domain_cache)
            source_ip = record.source_ip
            summary.header_from_counts[header_from] = (
                summary.header_from_counts.get(header_from, 0) + count
            )
            _bump_nested_counter(summary.source_header_from_counts, source_ip, header_from, count)
            if envelope_from:
                summary.envelope_from_counts[envelope_from] = (
                    summary.envelope_from_counts.get(envelope_from, 0) + count
                )
                _bump_nested_counter(
                    summary.source_envelope_from_counts,
                    source_ip,
                    envelope_from,
                    count,
                )

            summary.messages_total += count
            if report_day:
                summary.messages_by_day[report_day] = (
                    summary.messages_by_day.get(report_day, 0) + count
                )
                _bump_nested_counter(
                    summary.source_day_message_counts,
                    source_ip,
                    report_day,
                    count,
                )
            summary.source_message_counts[source_ip] = (
                summary.source_message_counts.get(source_ip, 0) + count
            )
            disposition = record.disposition or "none"
            summary.disposition_counts[disposition] = (
                summary.disposition_counts.get(disposition, 0) + count
            )
            _bump_nested_counter(
                summary.source_disposition_counts,
                source_ip,
                disposition,
                count,
            )
            for reason in record.override_reasons:
                if reason:
                    summary.override_reason_counts[reason] = (
                        summary.override_reason_counts.get(reason, 0) + count
                    )
                    _bump_nested_counter(
                        summary.source_override_reason_counts,
                        source_ip,
                        reason,
                        count,
                    )

            dkim_auth_ok = _has_auth_pass(record.dkim_results)
            spf_auth_ok = _has_auth_pass(record.spf_results)
            for dkim_result in record.dkim_results:
                selector = (dkim_result.selector or "").strip().lower()
                if not selector:
                    continue
                summary.dkim_selector_counts[selector] = (
                    summary.dkim_selector_counts.get(selector, 0) + count
                )
                _bump_nested_counter(
                    summary.source_dkim_selector_counts,
                    source_ip,
                    selector,
                    count,
                )
                dkim_domain = _normalize_domain_cached(dkim_result.domain, normalized_domain_cache)
                if dkim_domain:
                    _bump_nested_counter(
                        summary.source_dkim_domain_counts,
                        source_ip,
                        dkim_domain,
                        count,
                    )
                dkim_result_name = (dkim_result.result or "").strip().lower() or "unknown"
                _bump_nested_counter(
                    summary.source_dkim_result_counts,
                    source_ip,
                    dkim_result_name,
                    count,
                )
            for spf_result in record.spf_results:
                spf_domain = _normalize_domain_cached(spf_result.domain, normalized_domain_cache)
                if spf_domain:
                    _bump_nested_counter(
                        summary.source_spf_domain_counts,
                        source_ip,
                        spf_domain,
                        count,
                    )
                spf_result_name = (spf_result.result or "").strip().lower() or "unknown"
                _bump_nested_counter(
                    summary.source_spf_result_counts,
                    source_ip,
                    spf_result_name,
                    count,
                )

            dkim_ok = _has_aligned_pass(
                record.dkim_results,
                header_from,
                report.adkim,
                normalized_domain_cache,
            )
            spf_ok = _has_aligned_pass(
                record.spf_results,
                header_from,
                report.aspf,
                normalized_domain_cache,
            )

            if dkim_auth_ok:
                summary.dkim_auth_pass_count += count
            if spf_auth_ok:
                summary.spf_auth_pass_count += count
            if dkim_ok:
                summary.dkim_aligned_pass_count += count
                if report_day:
                    summary.dkim_aligned_pass_by_day[report_day] = (
                        summary.dkim_aligned_pass_by_day.get(report_day, 0) + count
                    )
                summary.source_dkim_aligned_pass_counts[source_ip] = (
                    summary.source_dkim_aligned_pass_counts.get(source_ip, 0) + count
                )
            if spf_ok:
                summary.spf_aligned_pass_count += count
                if report_day:
                    summary.spf_aligned_pass_by_day[report_day] = (
                        summary.spf_aligned_pass_by_day.get(report_day, 0) + count
                    )
                summary.source_spf_aligned_pass_counts[source_ip] = (
                    summary.source_spf_aligned_pass_counts.get(source_ip, 0) + count
                )
            if dkim_auth_ok and not dkim_ok:
                summary.dkim_alignment_gap_count += count
                summary.dkim_alignment_gap_source_counts[source_ip] = (
                    summary.dkim_alignment_gap_source_counts.get(source_ip, 0) + count
                )
            if spf_auth_ok and not spf_ok:
                summary.spf_alignment_gap_count += count
                summary.spf_alignment_gap_source_counts[source_ip] = (
                    summary.spf_alignment_gap_source_counts.get(source_ip, 0) + count
                )
                gap_key = f"{header_from} <- {envelope_from or '(missing envelope_from)'}"
                summary.spf_alignment_gap_pair_counts[gap_key] = (
                    summary.spf_alignment_gap_pair_counts.get(gap_key, 0) + count
                )

            if dkim_auth_ok and spf_auth_ok:
                summary.auth_both_pass_count += count
            elif dkim_auth_ok:
                summary.auth_dkim_only_pass_count += count
            elif spf_auth_ok:
                summary.auth_spf_only_pass_count += count
            else:
                summary.auth_neither_pass_count += count

            if dkim_ok or spf_ok:
                summary.dmarc_pass_count += count
                if report_day:
                    summary.dmarc_pass_by_day[report_day] = (
                        summary.dmarc_pass_by_day.get(report_day, 0) + count
                    )
                summary.source_pass_counts[source_ip] = (
                    summary.source_pass_counts.get(source_ip, 0) + count
                )
            else:
                summary.dmarc_fail_count += count
                if report_day:
                    summary.dmarc_fail_by_day[report_day] = (
                        summary.dmarc_fail_by_day.get(report_day, 0) + count
                    )
                    _bump_nested_counter(
                        summary.source_day_fail_counts,
                        source_ip,
                        report_day,
                        count,
                    )
                summary.source_fail_counts[source_ip] = (
                    summary.source_fail_counts.get(source_ip, 0) + count
                )
                summary.failing_source_counts[source_ip] = (
                    summary.failing_source_counts.get(source_ip, 0) + count
                )
                if not record.dkim_results:
                    summary.source_fail_missing_dkim_counts[source_ip] = (
                        summary.source_fail_missing_dkim_counts.get(source_ip, 0) + count
                    )
                elif dkim_auth_ok and not dkim_ok:
                    summary.source_fail_dkim_unaligned_counts[source_ip] = (
                        summary.source_fail_dkim_unaligned_counts.get(source_ip, 0) + count
                    )
                elif not dkim_auth_ok:
                    summary.source_fail_dkim_auth_fail_counts[source_ip] = (
                        summary.source_fail_dkim_auth_fail_counts.get(source_ip, 0) + count
                    )
        if _should_emit_progress(index, total_reports):
            _emit_progress(
                progress_callback,
                processed_reports=index,
                total_reports=total_reports,
            )

    for summary in summary_by_domain.values():
        _append_recommendations(
            summary=summary,
            min_fail_rate_alert=min_fail_rate_alert,
            min_messages_alert=min_messages_alert,
        )

    return summary_by_domain


def report_set_to_unique_reports(
    reports: list[DmarcReport],
) -> tuple[list[DmarcReport], int]:
    seen: set[tuple[str, str, int, int, str]] = set()
    unique: list[DmarcReport] = []
    skipped = 0
    for report in reports:
        key = report.dedupe_key
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        unique.append(report)
    return unique, skipped


def _has_auth_pass(auth_results) -> bool:
    for result in auth_results:
        if result.result == "pass":
            return True
    return False


def _has_aligned_pass(
    auth_results,
    header_from: str,
    alignment_mode: str,
    normalized_domain_cache: dict[str, str],
) -> bool:
    if not header_from:
        return False
    strict = alignment_mode == "s"
    header_suffix = "." + header_from
    for result in auth_results:
        if result.result != "pass":
            continue
        auth = _normalize_domain_cached(result.domain, normalized_domain_cache)
        if not auth:
            continue
        if strict:
            if auth == header_from:
                return True
            continue
        # Relaxed alignment in DMARC is org-domain based. We approximate this with
        # subdomain checks so the tool remains dependency-free.
        if auth == header_from or auth.endswith(header_suffix) or header_from.endswith("." + auth):
            return True
    return False


def _normalize_domain(domain: str) -> str:
    value = (domain or "").strip().lower().strip(".")
    return value


def _normalize_domain_cached(domain: str, cache: dict[str, str]) -> str:
    key = domain or ""
    cached = cache.get(key)
    if cached is not None:
        return cached
    value = _normalize_domain(key)
    cache[key] = value
    return value


def _bump_nested_counter(
    outer: dict[str, dict[str, int]],
    key: str,
    inner_key: str,
    amount: int,
) -> None:
    bucket = outer.get(key)
    if bucket is None:
        bucket = {}
        outer[key] = bucket
    bucket[inner_key] = bucket.get(inner_key, 0) + amount


def _should_emit_progress(index: int, total: int) -> bool:
    if total <= 0:
        return False
    if index == total:
        return True
    if total <= 200:
        return index % 10 == 0
    return index % 50 == 0


def _emit_progress(callback: ProgressCallback | None, **payload: object) -> None:
    if callback is not None:
        callback(dict(payload))


def _report_day_key(report: DmarcReport) -> str:
    timestamp = report.date_end or report.date_begin
    if timestamp <= 0:
        return ""
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
    except (OSError, OverflowError, ValueError):
        return ""


def _append_recommendations(
    summary: DomainSummary,
    min_fail_rate_alert: float,
    min_messages_alert: int,
) -> None:
    summary.recommendations.clear()
    summary.issues.clear()
    summary.action_plan.clear()

    def add_issue(
        *,
        issue_id: str,
        category: str,
        severity: str,
        confidence: str,
        title: str,
        evidence: str,
        likely_cause: str,
        actions: list[str],
        evidence_details: dict[str, object] | None = None,
    ) -> None:
        summary.issues.append(
            {
                "id": issue_id,
                "category": category,
                "severity": severity,
                "confidence": confidence,
                "title": title,
                "evidence": evidence,
                "evidence_details": evidence_details or {},
                "likely_cause": likely_cause,
                "actions": actions,
            }
        )
        summary.recommendations.append(f"{title} {evidence}")
        for action in actions:
            _add_action_step(summary.action_plan, action)

    if summary.messages_total <= 0:
        add_issue(
            issue_id="no_message_records",
            category="data_quality",
            severity="high",
            confidence="high",
            title="No message records were parsed.",
            evidence="No aggregate message counts were present in parsed reports.",
            likely_cause=(
                "Reports were malformed or did not include aggregate rows."
            ),
            actions=[
                "Validate that uploaded files are DMARC aggregate XML reports.",
                "Re-export data and re-run analysis with a larger sample window.",
            ],
            evidence_details={
                "reports_seen": summary.reports_seen,
                "messages_total": summary.messages_total,
            },
        )
        return

    fail_rate = summary.dmarc_fail_count / summary.messages_total
    pass_rate = summary.dmarc_pass_count / summary.messages_total
    dkim_auth_rate = summary.dkim_auth_pass_count / summary.messages_total
    spf_auth_rate = summary.spf_auth_pass_count / summary.messages_total
    dkim_rate = summary.dkim_aligned_pass_count / summary.messages_total
    spf_rate = summary.spf_aligned_pass_count / summary.messages_total
    dkim_gap_rate = summary.dkim_alignment_gap_count / summary.messages_total
    spf_gap_rate = summary.spf_alignment_gap_count / summary.messages_total
    confidence = _confidence_for_messages(summary.messages_total)
    reject_actions = summary.disposition_counts.get("reject", 0)
    quarantine_actions = summary.disposition_counts.get("quarantine", 0)
    dominant_policy = "unknown"
    policy_consistency = 0.0
    if summary.policy_counts:
        dominant_policy, dominant_count = sorted(
            summary.policy_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[0]
        total_policy = sum(summary.policy_counts.values())
        if total_policy > 0:
            policy_consistency = dominant_count / total_policy

    top_source = None
    top_count = 0
    top_share = 0.0
    if summary.dmarc_fail_count > 0 and summary.failing_source_counts:
        top_source, top_count = sorted(
            summary.failing_source_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[0]
        top_share = top_count / summary.dmarc_fail_count

    top_reporter, top_reporter_reports = _top_counter_entry(summary.reporter_counts)
    top_override_reason, top_override_count = _top_counter_entry(summary.override_reason_counts)
    top_spf_gap_source, top_spf_gap_count = _top_counter_entry(summary.spf_alignment_gap_source_counts)
    top_spf_gap_pair, top_spf_gap_pair_count = _top_counter_entry(summary.spf_alignment_gap_pair_counts)
    top_dkim_gap_source, top_dkim_gap_count = _top_counter_entry(summary.dkim_alignment_gap_source_counts)
    forwarding_signals = {"forwarded", "trusted_forwarder", "mailing_list", "local_policy"}
    forwarding_related_count = sum(
        count
        for reason, count in summary.override_reason_counts.items()
        if reason in forwarding_signals
    )

    if summary.messages_total < min_messages_alert:
        add_issue(
            issue_id="limited_data",
            category="data_quality",
            severity="low",
            confidence="high",
            title="Limited report volume.",
            evidence=(
                f"Only {summary.messages_total} messages observed; thresholds are less reliable."
            ),
            likely_cause=(
                "Short reporting window or low send volume."
            ),
            actions=[
                "Collect at least 7 days of DMARC aggregate reports before policy changes.",
            ],
            evidence_details={
                "messages_total": summary.messages_total,
                "min_messages_alert": min_messages_alert,
            },
        )

    severe_fail_threshold = max(0.05, min_fail_rate_alert * 2.0)
    if summary.messages_total >= min_messages_alert and fail_rate >= severe_fail_threshold:
        add_issue(
            issue_id="high_dmarc_fail_rate",
            category="unauthorized_or_misconfigured_sources",
            severity="high",
            confidence=confidence,
            title="DMARC fail rate is materially high.",
            evidence=(
                f"{fail_rate:.2%} of {summary.messages_total} messages failed DMARC."
            ),
            likely_cause=(
                "Either unauthorized senders are impersonating the domain or legitimate sender "
                "paths are missing aligned DKIM/SPF authentication."
            ),
            actions=[
                "Start with top failing sources and map each source IP/hostname to a known sender platform.",
                "For legitimate platforms, enable aligned DKIM signing and aligned SPF MAIL FROM domains.",
                "Block, decommission, or tightly restrict unknown sender infrastructure.",
                "Re-check fail rate after 48-72 hours of changes.",
            ],
            evidence_details={
                "fail_rate": round(fail_rate, 6),
                "fail_count": summary.dmarc_fail_count,
                "top_failing_source": top_source,
                "top_failing_source_messages": top_count,
                "top_failing_source_share": round(top_share, 6),
                "top_reporter_org": top_reporter,
                "top_reporter_reports": top_reporter_reports,
            },
        )
    elif summary.messages_total >= min_messages_alert and fail_rate >= min_fail_rate_alert:
        add_issue(
            issue_id="elevated_dmarc_fail_rate",
            category="unauthorized_or_misconfigured_sources",
            severity="medium",
            confidence=confidence,
            title="DMARC fail rate is above target.",
            evidence=(
                f"{fail_rate:.2%} of {summary.messages_total} messages failed DMARC."
            ),
            likely_cause=(
                "One or more sender paths are failing aligned authentication."
            ),
            actions=[
                "Review top failing sources and identify which are legitimate systems.",
                "Fix alignment for legitimate senders before tightening DMARC policy.",
            ],
            evidence_details={
                "fail_rate": round(fail_rate, 6),
                "fail_count": summary.dmarc_fail_count,
                "top_failing_source": top_source,
                "top_failing_source_messages": top_count,
            },
        )

    if dominant_policy == "none":
        severity = (
            "low"
            if summary.messages_total >= min_messages_alert and fail_rate <= 0.01
            else "medium"
        )
        add_issue(
            issue_id="monitor_only_policy",
            category="policy_posture",
            severity=severity,
            confidence=confidence,
            title="Domain is still in monitor-only mode (p=none).",
            evidence=(
                f"Published policy is mostly p=none (consistency {policy_consistency:.0%})."
            ),
            likely_cause=(
                "Policy has not been moved into enforcement yet, usually due to unresolved sender coverage."
            ),
            actions=[
                "If fail rate is stable <=1%, move to p=quarantine with pct=25 for a staged rollout.",
                "Increase pct to 100 once legitimate traffic impact is validated.",
                "Move to p=reject after at least one stable reporting cycle.",
            ],
            evidence_details={
                "dominant_policy": dominant_policy,
                "policy_consistency": round(policy_consistency, 6),
                "fail_rate": round(fail_rate, 6),
            },
        )
    elif dominant_policy == "quarantine" and summary.messages_total >= min_messages_alert:
        add_issue(
            issue_id="quarantine_policy",
            category="policy_posture",
            severity="low",
            confidence=confidence,
            title="Domain is enforcing quarantine policy.",
            evidence=(
                f"Policy is mostly p=quarantine (consistency {policy_consistency:.0%})."
            ),
            likely_cause=(
                "Reject policy has not yet been rolled out or is intentionally deferred."
            ),
            actions=[
                "If fail rate remains low and business impact is acceptable, test p=reject.",
            ],
            evidence_details={
                "dominant_policy": dominant_policy,
                "policy_consistency": round(policy_consistency, 6),
            },
        )

    if dkim_auth_rate <= 0:
        add_issue(
            issue_id="no_dkim_authentication",
            category="legitimate_misconfiguration",
            severity="high",
            confidence=confidence,
            title="No DKIM authentication passes were observed.",
            evidence="DKIM auth pass count is zero.",
            likely_cause=(
                "DKIM is not configured for active senders or signatures are invalid."
            ),
            actions=[
                "Turn on DKIM signing in each sender platform and align d= with header-from domain.",
                "Publish and verify selector TXT records in DNS.",
            ],
            evidence_details={
                "dkim_auth_pass_rate": round(dkim_auth_rate, 6),
                "dkim_aligned_pass_rate": round(dkim_rate, 6),
            },
        )
    elif dkim_rate < 0.85:
        severity = "high" if dkim_rate < 0.65 else "medium"
        add_issue(
            issue_id="low_dkim_alignment",
            category="alignment_gap",
            severity=severity,
            confidence=confidence,
            title="DKIM alignment coverage is low.",
            evidence=(
                f"DKIM auth pass is {dkim_auth_rate:.2%}, but aligned DKIM is {dkim_rate:.2%}."
            ),
            likely_cause=(
                "Some senders are not DKIM-signing with an aligned d= domain, "
                "or signatures are getting broken in transit."
            ),
            actions=[
                "Enable DKIM signing for each sender platform using your domain or aligned subdomain.",
                "Validate DKIM selectors and key DNS records for each sending service.",
                "Check forwarding/list transformations that may invalidate DKIM signatures.",
            ],
            evidence_details={
                "dkim_auth_pass_rate": round(dkim_auth_rate, 6),
                "dkim_aligned_pass_rate": round(dkim_rate, 6),
                "dkim_alignment_gap_rate": round(dkim_gap_rate, 6),
                "top_gap_source": top_dkim_gap_source,
                "top_gap_source_messages": top_dkim_gap_count,
            },
        )

    if spf_auth_rate <= 0:
        add_issue(
            issue_id="no_spf_authentication",
            category="legitimate_misconfiguration",
            severity="high",
            confidence=confidence,
            title="No SPF authentication passes were observed.",
            evidence="SPF auth pass count is zero.",
            likely_cause=(
                "SPF records may be missing, broken, or not published for active sender envelope domains."
            ),
            actions=[
                "Publish SPF on aligned envelope-from domains for each sending platform.",
                "Confirm MAIL FROM domains are aligned to the visible header-from domain.",
            ],
            evidence_details={
                "spf_auth_pass_rate": round(spf_auth_rate, 6),
                "spf_aligned_pass_rate": round(spf_rate, 6),
            },
        )
    elif spf_rate < 0.8 or spf_gap_rate >= 0.05:
        severity = "high" if spf_rate < 0.6 else "medium"
        add_issue(
            issue_id="low_spf_alignment",
            category="alignment_gap",
            severity=severity,
            confidence=confidence,
            title="SPF alignment coverage is low.",
            evidence=(
                f"SPF auth pass is {spf_auth_rate:.2%}, but aligned SPF is {spf_rate:.2%}."
            ),
            likely_cause=(
                "Envelope-from (Return-Path) domains are not aligned to header-from, "
                "or SPF records do not authorize all legitimate sending hosts."
            ),
            actions=[
                "For each sender service, configure a custom MAIL FROM/Return-Path domain under your domain.",
                "Publish SPF records on those envelope domains including all legitimate sender infrastructure.",
                "Keep SPF under DNS lookup limits and flatten where needed.",
            ],
            evidence_details={
                "spf_auth_pass_rate": round(spf_auth_rate, 6),
                "spf_aligned_pass_rate": round(spf_rate, 6),
                "spf_alignment_gap_rate": round(spf_gap_rate, 6),
                "top_gap_source": top_spf_gap_source,
                "top_gap_source_messages": top_spf_gap_count,
                "top_alignment_gap_pair": top_spf_gap_pair,
                "top_alignment_gap_pair_messages": top_spf_gap_pair_count,
            },
        )

    if dkim_rate - spf_rate >= 0.15:
        add_issue(
            issue_id="spf_trails_dkim",
            category="alignment_gap",
            severity="medium",
            confidence=confidence,
            title="SPF alignment trails DKIM.",
            evidence=(
                f"DKIM aligned pass is {dkim_rate:.2%} vs SPF aligned {spf_rate:.2%} "
                f"(SPF auth {spf_auth_rate:.2%})."
            ),
            likely_cause=(
                "SPF may pass on non-aligned envelope domains while DKIM handles most aligned auth."
            ),
            actions=[
                "Audit envelope-from domains used by each sender and align them to your domain.",
                "Update SPF include chains for all legitimate senders.",
            ],
            evidence_details={
                "dkim_aligned_pass_rate": round(dkim_rate, 6),
                "spf_aligned_pass_rate": round(spf_rate, 6),
                "spf_auth_pass_rate": round(spf_auth_rate, 6),
            },
        )

    if (
        spf_gap_rate >= 0.05
        and dkim_rate >= 0.9
        and fail_rate <= 0.08
    ):
        add_issue(
            issue_id="possible_indirect_flow_noise",
            category="infrastructure_signal",
            severity="low",
            confidence=confidence,
            title="A portion of failures may be indirect-flow or receiver-side relay noise.",
            evidence=(
                f"SPF alignment gap is {spf_gap_rate:.2%} while DKIM alignment remains {dkim_rate:.2%}."
            ),
            likely_cause=(
                "Recipient-side relay/security scanning or forwarding can break SPF alignment "
                "without indicating your own sender infrastructure is compromised."
            ),
            actions=[
                "Do not whitelist third-party relay IPs in SPF unless they are confirmed sender paths.",
                "Prioritize aligned DKIM coverage for legitimate sender platforms.",
                "Treat receiver-side relay-classified failing sources as lower-priority investigation targets.",
            ],
            evidence_details={
                "spf_alignment_gap_rate": round(spf_gap_rate, 6),
                "dkim_aligned_pass_rate": round(dkim_rate, 6),
                "dmarc_fail_rate": round(fail_rate, 6),
            },
        )

    if summary.dmarc_fail_count > 0 and top_source is not None and top_share >= 0.35:
        severity = "high" if top_share >= 0.6 else "medium"
        add_issue(
            issue_id="failure_concentration",
            category="unauthorized_or_misconfigured_sources",
            severity=severity,
            confidence=confidence,
            title="Failures are concentrated on a narrow source set.",
            evidence=(
                f"{top_source} accounts for {top_share:.1%} of failing messages "
                f"({top_count} of {summary.dmarc_fail_count})."
            ),
            likely_cause=(
                "A single sender platform or abuse source is driving most DMARC failures."
            ),
            actions=[
                "Prioritize investigation and remediation of the top failing source first.",
                "Confirm whether that source is an approved sender, then fix or block it.",
            ],
            evidence_details={
                "top_failing_source": top_source,
                "top_failing_source_messages": top_count,
                "top_failing_source_share": round(top_share, 6),
            },
        )

    enforced_actions = reject_actions + quarantine_actions
    if (
        summary.dmarc_fail_count > 0
        and dominant_policy != "none"
        and enforced_actions < summary.dmarc_fail_count
    ):
        enforcement_ratio = enforced_actions / summary.dmarc_fail_count
        add_issue(
            issue_id="partial_enforcement",
            category="enforcement_gap",
            severity="low",
            confidence=confidence,
            title="Observed enforcement on failures is partial.",
            evidence=(
                f"Only {enforcement_ratio:.1%} of failing messages show quarantine/reject dispositions."
            ),
            likely_cause=(
                "pct may be below 100, policy has changed over time, or reports span mixed policy windows."
            ),
            actions=[
                "Verify DMARC record pct value and recent policy history.",
                "Increase pct gradually toward 100 as false positives are resolved.",
            ],
            evidence_details={
                "failing_messages": summary.dmarc_fail_count,
                "enforced_failures": enforced_actions,
                "enforcement_ratio": round(enforcement_ratio, 6),
            },
        )

    if summary.reports_seen >= 3 and policy_consistency < 0.9:
        add_issue(
            issue_id="policy_drift",
            category="policy_posture",
            severity="low",
            confidence=confidence,
            title="Policy posture changed during the reporting window.",
            evidence=(
                f"Dominant policy consistency is {policy_consistency:.1%} across reports."
            ),
            likely_cause=(
                "DMARC policy updates were rolled out during the analyzed date range."
            ),
            actions=[
                "Filter reports to a narrower date window when validating policy impact.",
            ],
            evidence_details={
                "policy_counts": dict(summary.policy_counts),
                "policy_consistency": round(policy_consistency, 6),
            },
        )

    if forwarding_related_count > 0 and summary.dmarc_fail_count > 0:
        add_issue(
            issue_id="forwarding_override_signals",
            category="infrastructure_signal",
            severity="low",
            confidence=confidence,
            title="Forwarding/local-policy override signals were observed.",
            evidence=(
                f"{forwarding_related_count} messages include override reasons such as "
                "forwarded/trusted_forwarder/mailing_list/local_policy."
            ),
            likely_cause=(
                "Forwarding and intermediary handling can break SPF and occasionally DKIM, "
                "causing DMARC failures that are not pure spoofing."
            ),
            actions=[
                "Prioritize DKIM alignment for legitimate sender paths because DKIM survives forwarding better than SPF.",
                "Review override-reason traffic before treating all failures as malicious.",
            ],
            evidence_details={
                "top_override_reason": top_override_reason,
                "top_override_reason_messages": top_override_count,
                "override_reason_counts": dict(summary.override_reason_counts),
            },
        )

    if not summary.issues:
        add_issue(
            issue_id="healthy_posture",
            category="healthy_posture",
            severity="low",
            confidence=confidence,
            title="No major DMARC posture issues detected.",
            evidence=f"DMARC pass rate is {pass_rate:.2%} across {summary.messages_total} messages.",
            likely_cause=(
                "Alignment and fail rates are within expected thresholds."
            ),
            actions=[
                "Continue monitoring aggregate reports and rotate DKIM keys on schedule.",
            ],
            evidence_details={
                "pass_rate": round(pass_rate, 6),
                "messages_total": summary.messages_total,
            },
        )

    summary.issues.sort(
        key=lambda item: (
            _severity_rank(str(item.get("severity", "low"))),
            _confidence_rank(str(item.get("confidence", "low"))),
        )
    )

    # Keep recommendations concise and derived from top diagnosed issues.
    summary.recommendations = [
        (
            f"[{item.get('severity', 'low')}/{item.get('category', 'general')}/"
            f"{item.get('confidence', 'low')}] {item.get('title', '')} "
            f"{item.get('evidence', '')}"
        ).strip()
        for item in summary.issues[:4]
    ]
    if not summary.action_plan:
        summary.action_plan = ["Continue monitoring DMARC reports for regressions."]


def _confidence_for_messages(messages_total: int) -> str:
    if messages_total >= 2000:
        return "high"
    if messages_total >= 500:
        return "medium"
    return "low"


def _top_counter_entry(counts: dict[str, int]) -> tuple[str | None, int]:
    if not counts:
        return None, 0
    key, value = sorted(counts.items(), key=lambda item: item[1], reverse=True)[0]
    return key, value


def _severity_rank(value: str) -> int:
    table = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return table.get(value.lower(), 5)


def _confidence_rank(value: str) -> int:
    table = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }
    return table.get(value.lower(), 3)


def _add_action_step(action_plan: list[str], step: str) -> None:
    normalized = step.strip()
    if not normalized:
        return
    if normalized not in action_plan:
        action_plan.append(normalized)
