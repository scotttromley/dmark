from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import models as _model_exports
from .action_plan import _build_dynamic_action_plan
from .classification import (
    _M365_HEAVY_MESSAGE_SHARE_THRESHOLD,
    _classify_source,
    _dynamic_auto_approve_min_volume,
    _is_m365_dkim_carrying_load,
    _select_m365_alignment_sender,
)
from .scoring import (
    _anti_spoofing_posture_score,
    _attack_pressure_assessment,
    _deliverability_safety_note,
    _deliverability_safety_score,
    _dominant_policy,
    _enforcement_readiness_assessment,
    _has_high_risk_findings,
    _health_label,
    _health_score_and_breakdown,
    _health_score_causes,
    _legitimate_basis,
    _policy_impact_simulation,
    _protection_posture_assessment,
    _reframe_issues_for_attack_pressure,
    _score_confidence,
)
from .time_series import (
    _build_daily_time_series,
    _legitimate_day_basis_counts,
    _legitimate_dkim_failure_modes,
    _source_dkim_failure_mode,
    _sum_day_counts_for_sources,
    _top_items,
    _top_items_for_source,
)

if TYPE_CHECKING:
    from .models import DomainSummary


_FORWARDING_REASON_TYPES = {
    "forwarded",
    "trusted_forwarder",
    "mailing_list",
    "local_policy",
}


@dataclass
class _SourceAnalysisResult:
    top_failing_sources: list[tuple[str, int]]
    sorted_senders: list[tuple[str, int]]
    top_failing_source_items: list[dict[str, object]]
    receiver_side_security_sources: list[dict[str, object]]
    sender_inventory_items: list[dict[str, object]]
    classified_sources: dict[str, dict[str, str]]
    auto_approved_sender_ips: set[str]
    noise_sender_ips: set[str]


@dataclass
class _SenderRollupResult:
    receiver_side_security_fail_count: int
    receiver_side_security_fail_share: float
    noise_message_count: int
    noise_fail_count: int
    m365_sender_ips: set[str]
    m365_message_count: int
    m365_fail_count: int
    m365_message_rate: float
    is_m365_heavy: bool
    effective_approved_senders: set[str]
    sender_inventory_summary: dict[str, object]


def _build_source_evidence_details(
    summary: DomainSummary,
    source_ip: str,
) -> dict[str, object]:
    return {
        "top_header_from": _top_items_for_source(
            summary.source_header_from_counts,
            source_ip,
            limit=3,
        ),
        "top_envelope_from": _top_items_for_source(
            summary.source_envelope_from_counts,
            source_ip,
            limit=3,
        ),
        "top_dispositions": _top_items_for_source(
            summary.source_disposition_counts,
            source_ip,
            limit=3,
        ),
        "top_override_reasons": _top_items_for_source(
            summary.source_override_reason_counts,
            source_ip,
            limit=3,
        ),
        "top_dkim_selectors": _top_items_for_source(
            summary.source_dkim_selector_counts,
            source_ip,
            limit=3,
        ),
        "top_dkim_domains": _top_items_for_source(
            summary.source_dkim_domain_counts,
            source_ip,
            limit=3,
        ),
        "top_dkim_results": _top_items_for_source(
            summary.source_dkim_result_counts,
            source_ip,
            limit=3,
        ),
        "top_spf_domains": _top_items_for_source(
            summary.source_spf_domain_counts,
            source_ip,
            limit=3,
        ),
        "top_spf_results": _top_items_for_source(
            summary.source_spf_result_counts,
            source_ip,
            limit=3,
        ),
        "aggregate_record_notice": (
            "DMARC aggregate reports provide record-level buckets, not individual email events."
        ),
    }


def _build_source_analysis(
    summary: DomainSummary,
    *,
    resolve_source_ips: bool,
    approved_senders: set[str],
    previous_sender_history: set[str],
) -> _SourceAnalysisResult:
    top_failing_sources = sorted(
        summary.failing_source_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:10]
    sorted_senders = sorted(
        summary.source_message_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    )
    top_failing_source_items: list[dict[str, object]] = []
    receiver_side_security_sources: list[dict[str, object]] = []
    sender_inventory_items: list[dict[str, object]] = []
    resolved_hostnames: dict[str, str | None] = {}
    classified_sources: dict[str, dict[str, str]] = {}
    auto_approved_sender_ips: set[str] = set()
    noise_sender_ips: set[str] = set()
    dynamic_min_auto_approve_volume = _dynamic_auto_approve_min_volume(
        summary.messages_total
    )

    def classify_sender(
        source_ip: str,
        sender_count: int,
        sender_pass_rate: float,
        hostname_hint: str | None = None,
        allow_auto_approve: bool = True,
    ) -> dict[str, str]:
        classification = classified_sources.get(source_ip)
        hostname = hostname_hint
        if hostname is None and source_ip in resolved_hostnames:
            hostname = resolved_hostnames[source_ip]
        if classification is None or (
            hostname and classification.get("category") == "unknown"
        ):
            classification = _classify_source(source_ip, hostname)
        if (
            allow_auto_approve
            and classification.get("category") == "unknown"
            and classification.get("legit_status") == "pending_review"
            and sender_count >= dynamic_min_auto_approve_volume
            and sender_pass_rate >= 0.98
        ):
            classification = {
                "category": "observed_high_pass_sender",
                "legit_status": "approved",
                "action": "monitor",
                "confidence": "medium",
                "reason": (
                    "Observed sender has >=98% DMARC pass rate and meets auto-approval "
                    f"minimum volume ({dynamic_min_auto_approve_volume} messages) in the "
                    "current report window."
                ),
            }
        classified_sources[source_ip] = classification
        if classification["legit_status"] == "noise":
            noise_sender_ips.add(source_ip)
        if classification["legit_status"] == "approved":
            auto_approved_sender_ips.add(source_ip)
        return classification

    for index, (source_ip, count) in enumerate(top_failing_sources):
        hostname = resolved_hostnames.get(source_ip)
        if source_ip not in resolved_hostnames and resolve_source_ips and index < 3:
            hostname = _model_exports._reverse_dns(source_ip)
            resolved_hostnames[source_ip] = hostname
        sender_total = summary.source_message_counts.get(source_ip, count)
        sender_pass = summary.source_pass_counts.get(source_ip, 0)
        sender_pass_rate = (sender_pass / sender_total) if sender_total > 0 else 0.0
        source_classification = classify_sender(
            source_ip=source_ip,
            sender_count=sender_total,
            sender_pass_rate=sender_pass_rate,
            hostname_hint=hostname,
            allow_auto_approve=False,
        )
        source_category = source_classification["category"]
        source_legit_status = source_classification["legit_status"]
        source_action = source_classification["action"]
        source_confidence = source_classification["confidence"]
        source_reason = source_classification["reason"]
        source_override_counts = summary.source_override_reason_counts.get(source_ip, {})
        source_forwarding_override_count = sum(
            count
            for reason, count in source_override_counts.items()
            if reason in _FORWARDING_REASON_TYPES
        )
        source_forwarding_override_rate = (
            (source_forwarding_override_count / sender_total)
            if sender_total > 0
            else 0.0
        )
        investigation_confidence = source_confidence
        investigation_note = ""
        if source_forwarding_override_count > 0 and source_category != "receiver_security_relay":
            if source_forwarding_override_rate >= 0.4:
                investigation_confidence = "low"
            elif source_forwarding_override_rate >= 0.15 and source_confidence == "high":
                investigation_confidence = "medium"
            investigation_note = (
                "Indirect-flow overrides were observed for this source. Forwarding commonly breaks SPF; "
                "DKIM may still pass unless content is modified in transit."
            )
        source_failure_mode = _source_dkim_failure_mode(
            source_ip=source_ip,
            missing_dkim_counts=summary.source_fail_missing_dkim_counts,
            dkim_auth_fail_counts=summary.source_fail_dkim_auth_fail_counts,
            dkim_unaligned_counts=summary.source_fail_dkim_unaligned_counts,
        )
        top_failing_source_items.append(
            {
                "source_ip": source_ip,
                "message_count": count,
                "hostname": hostname,
                "classification": source_category,
                "classification_confidence": source_confidence,
                "classification_reason": source_reason,
                "category": source_category,
                "legit_status": source_legit_status,
                "action": source_action,
                "investigation_confidence": investigation_confidence,
                "investigation_note": investigation_note,
                "dkim_failure_mode": source_failure_mode,
                "fail_share_rate": round(
                    (count / summary.dmarc_fail_count) if summary.dmarc_fail_count > 0 else 0.0,
                    6,
                ),
                "evidence_details": _build_source_evidence_details(summary, source_ip),
            }
        )
        if source_category == "receiver_security_relay":
            receiver_side_security_sources.append(
                {
                    "source_ip": source_ip,
                    "hostname": hostname,
                    "message_count": count,
                    "classification_confidence": source_confidence,
                }
            )

    for source_ip, count in sorted_senders[:20]:
        sender_fail = summary.source_fail_counts.get(source_ip, 0)
        sender_pass = summary.source_pass_counts.get(source_ip, 0)
        sender_pass_rate = (sender_pass / count) if count > 0 else 0.0
        hostname = resolved_hostnames.get(source_ip)
        classification = classify_sender(
            source_ip=source_ip,
            sender_count=count,
            sender_pass_rate=sender_pass_rate,
            hostname_hint=hostname,
        )
        approved_sender_flag = (
            source_ip in approved_senders
            or classification["legit_status"] == "approved"
        )
        sender_inventory_items.append(
            {
                "source_ip": source_ip,
                "message_count": count,
                "dmarc_pass_count": sender_pass,
                "dmarc_fail_count": sender_fail,
                "dmarc_fail_rate": round((sender_fail / count) if count > 0 else 0.0, 6),
                "dmarc_pass_rate": round(sender_pass_rate, 6),
                "message_share_rate": round((count / summary.messages_total), 6)
                if summary.messages_total > 0
                else 0.0,
                "approved_sender": approved_sender_flag,
                "new_since_last_run": source_ip not in previous_sender_history,
                "hostname": hostname,
                "classification": classification["category"],
                "classification_confidence": classification["confidence"],
                "classification_reason": classification["reason"],
                "legit_status": classification["legit_status"],
                "suggested_action": classification["action"],
            }
        )

    # Apply auto-approval and noise classification to the full sender set so
    # readiness coverage isn't limited to the top-N sender display.
    for source_ip, count in sorted_senders[20:]:
        sender_pass = summary.source_pass_counts.get(source_ip, 0)
        sender_pass_rate = (sender_pass / count) if count > 0 else 0.0
        classify_sender(
            source_ip=source_ip,
            sender_count=count,
            sender_pass_rate=sender_pass_rate,
        )

    return _SourceAnalysisResult(
        top_failing_sources=top_failing_sources,
        sorted_senders=sorted_senders,
        top_failing_source_items=top_failing_source_items,
        receiver_side_security_sources=receiver_side_security_sources,
        sender_inventory_items=sender_inventory_items,
        classified_sources=classified_sources,
        auto_approved_sender_ips=auto_approved_sender_ips,
        noise_sender_ips=noise_sender_ips,
    )


def _build_dns_diagnostics(
    domain: str,
    top_dkim_selectors: list[dict[str, object]],
    *,
    resolve_dns_records: bool,
) -> dict[str, object]:
    observed_selectors = [str(item.get("name", "")) for item in top_dkim_selectors]
    if resolve_dns_records:
        return _model_exports._resolve_domain_dns_diagnostics(domain, observed_selectors)
    return {
        "enabled": False,
        "reason": "DNS diagnostics disabled for this run.",
        "domain": domain,
    }


def _build_dns_action_hints(
    domain: str,
    dns_diagnostics: dict[str, object],
) -> list[str]:
    hints: list[str] = []
    if not dns_diagnostics.get("enabled"):
        return hints
    if not dns_diagnostics.get("dmarc_record_found"):
        hints.append(
            f"DNS check could not confirm a DMARC TXT record at _dmarc.{domain}. Verify the live record."
        )
    if not dns_diagnostics.get("spf_record_found"):
        hints.append(
            f"DNS check could not confirm an SPF TXT record at {domain}. Verify envelope domains and SPF publication."
        )
    if dns_diagnostics.get("m365_dkim_status") == "partial":
        hints.append(
            "Only one of selector1/selector2 appears to target M365 DKIM. Publish both selectors before enabling DKIM."
        )
    return hints


def _build_sender_rollups(
    summary: DomainSummary,
    *,
    approved_senders: set[str],
    auto_approved_sender_ips: set[str],
    noise_sender_ips: set[str],
    classified_sources: dict[str, dict[str, str]],
) -> _SenderRollupResult:
    sender_rollups = _build_sender_rollups(
        summary,
        approved_senders=approved_senders,
        auto_approved_sender_ips=auto_approved_sender_ips,
        noise_sender_ips=noise_sender_ips,
        classified_sources=classified_sources,
    )
    receiver_side_security_fail_count = sender_rollups.receiver_side_security_fail_count
    receiver_side_security_fail_share = sender_rollups.receiver_side_security_fail_share
    noise_message_count = sender_rollups.noise_message_count
    noise_fail_count = sender_rollups.noise_fail_count
    m365_sender_ips = sender_rollups.m365_sender_ips
    m365_message_count = sender_rollups.m365_message_count
    m365_fail_count = sender_rollups.m365_fail_count
    m365_message_rate = sender_rollups.m365_message_rate
    is_m365_heavy = sender_rollups.is_m365_heavy
    effective_approved_senders = sender_rollups.effective_approved_senders
    sender_inventory_summary = sender_rollups.sender_inventory_summary
    return _SenderRollupResult(
        receiver_side_security_fail_count=receiver_side_security_fail_count,
        receiver_side_security_fail_share=receiver_side_security_fail_share,
        noise_message_count=noise_message_count,
        noise_fail_count=noise_fail_count,
        m365_sender_ips=m365_sender_ips,
        m365_message_count=m365_message_count,
        m365_fail_count=m365_fail_count,
        m365_message_rate=m365_message_rate,
        is_m365_heavy=is_m365_heavy,
        effective_approved_senders=effective_approved_senders,
        sender_inventory_summary=sender_inventory_summary,
    )


def _annotate_sender_inventory_labels(
    sender_inventory_items: list[dict[str, object]],
    *,
    m365_dkim_carrying_load: bool,
    dkim_rate: float,
) -> None:
    for item in sender_inventory_items:
        classification_name = str(item.get("classification", "unknown"))
        legit_status = str(item.get("legit_status", "pending_review"))
        suggested_action = str(item.get("suggested_action", "investigate"))
        legit_status_label = legit_status.replace("_", " ")
        suggested_action_label = suggested_action.replace("_", " ")
        if classification_name == "esp_microsoft365_outbound":
            if m365_dkim_carrying_load:
                legit_status_label = "approved (DKIM carrying load)"
                suggested_action_label = "monitor - no action needed"
            elif dkim_rate < 0.90 and suggested_action == "fix_alignment":
                suggested_action_label = "fix alignment (DKIM coverage low)"
        item["legit_status_label"] = legit_status_label
        item["suggested_action_label"] = suggested_action_label


def build_domain_summary_payload(
    summary: DomainSummary,
    resolve_source_ips: bool = False,
    resolve_dns_records: bool = False,
    previous_sender_history: set[str] | None = None,
    approved_senders: set[str] | None = None,
) -> dict[str, object]:
    previous_sender_history = previous_sender_history or set()
    approved_senders = approved_senders or set()
    pass_rate = (
        (summary.dmarc_pass_count / summary.messages_total) if summary.messages_total else 0.0
    )
    fail_rate = (
        (summary.dmarc_fail_count / summary.messages_total) if summary.messages_total else 0.0
    )
    dkim_rate = (
        (summary.dkim_aligned_pass_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    dkim_auth_rate = (
        (summary.dkim_auth_pass_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    spf_rate = (
        (summary.spf_aligned_pass_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    spf_auth_rate = (
        (summary.spf_auth_pass_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    dkim_alignment_gap_rate = (
        (summary.dkim_alignment_gap_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    spf_alignment_gap_rate = (
        (summary.spf_alignment_gap_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    auth_both_pass_rate = (
        (summary.auth_both_pass_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    auth_dkim_only_pass_rate = (
        (summary.auth_dkim_only_pass_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    auth_spf_only_pass_rate = (
        (summary.auth_spf_only_pass_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    auth_neither_pass_rate = (
        (summary.auth_neither_pass_count / summary.messages_total)
        if summary.messages_total
        else 0.0
    )
    average_policy_pct = (
        (summary.policy_pct_total / summary.policy_pct_reports)
        if summary.policy_pct_reports > 0
        else 100.0
    )

    dominant_policy, policy_consistency = _dominant_policy(summary.policy_counts)
    enforcement_actions = summary.disposition_counts.get("quarantine", 0) + summary.disposition_counts.get(
        "reject", 0
    )
    reject_actions = summary.disposition_counts.get("reject", 0)
    enforcement_observed_rate = (
        (enforcement_actions / summary.messages_total) if summary.messages_total else 0.0
    )
    health_score, health_breakdown = _health_score_and_breakdown(
        fail_rate=fail_rate,
        dkim_rate=dkim_rate,
        spf_rate=spf_rate,
        dominant_policy=dominant_policy,
    )
    health_label = _health_label(health_score)
    health_causes = _health_score_causes(health_breakdown)

    top_reporters = _top_items(summary.reporter_counts, limit=5, value_key="report_count")
    top_override_reasons = _top_items(
        summary.override_reason_counts,
        limit=5,
        value_key="message_count",
    )
    top_header_from = _top_items(summary.header_from_counts, limit=5, value_key="message_count")
    top_envelope_from = _top_items(
        summary.envelope_from_counts,
        limit=5,
        value_key="message_count",
    )
    top_spf_alignment_gap_pairs = _top_items(
        summary.spf_alignment_gap_pair_counts,
        limit=5,
        value_key="message_count",
    )
    top_dkim_selectors = _top_items(
        summary.dkim_selector_counts,
        limit=5,
        value_key="message_count",
    )
    source_analysis = _build_source_analysis(
        summary,
        resolve_source_ips=resolve_source_ips,
        approved_senders=approved_senders,
        previous_sender_history=previous_sender_history,
    )
    top_failing_sources = source_analysis.top_failing_sources
    sorted_senders = source_analysis.sorted_senders
    top_failing_source_items = source_analysis.top_failing_source_items
    receiver_side_security_sources = source_analysis.receiver_side_security_sources
    sender_inventory_items = source_analysis.sender_inventory_items
    classified_sources = source_analysis.classified_sources
    auto_approved_sender_ips = source_analysis.auto_approved_sender_ips
    noise_sender_ips = source_analysis.noise_sender_ips

    top_source_share = 0.0
    if summary.dmarc_fail_count > 0 and top_failing_sources:
        top_source_share = top_failing_sources[0][1] / summary.dmarc_fail_count

    receiver_side_security_fail_count = sum(
        summary.source_fail_counts.get(source_ip, 0)
        for source_ip in noise_sender_ips
        if classified_sources.get(source_ip, {}).get("category") == "receiver_security_relay"
    )
    receiver_side_security_fail_share = (
        (receiver_side_security_fail_count / summary.dmarc_fail_count)
        if summary.dmarc_fail_count > 0
        else 0.0
    )
    noise_message_count = sum(
        summary.source_message_counts.get(source_ip, 0) for source_ip in noise_sender_ips
    )
    noise_fail_count = sum(
        summary.source_fail_counts.get(source_ip, 0) for source_ip in noise_sender_ips
    )
    m365_sender_ips = {
        source_ip
        for source_ip, classification in classified_sources.items()
        if classification.get("category") == "esp_microsoft365_outbound"
    }
    m365_message_count = sum(
        summary.source_message_counts.get(source_ip, 0) for source_ip in m365_sender_ips
    )
    m365_fail_count = sum(
        summary.source_fail_counts.get(source_ip, 0) for source_ip in m365_sender_ips
    )
    m365_message_rate = (
        (m365_message_count / summary.messages_total) if summary.messages_total > 0 else 0.0
    )
    is_m365_heavy = (
        m365_message_count > 0 and m365_message_rate >= _M365_HEAVY_MESSAGE_SHARE_THRESHOLD
    )
    effective_approved_senders = {
        source_ip
        for source_ip in set(approved_senders) | set(auto_approved_sender_ips)
        if source_ip not in noise_sender_ips
    }
    approved_message_count = sum(
        summary.source_message_counts.get(source_ip, 0) for source_ip in effective_approved_senders
    )
    pending_review_message_count = max(
        0,
        summary.messages_total - approved_message_count - noise_message_count,
    )
    sender_inventory_summary = {
        "approved_messages": approved_message_count,
        "approved_rate": round(
            (approved_message_count / summary.messages_total) if summary.messages_total > 0 else 0.0,
            6,
        ),
        "noise_messages": noise_message_count,
        "noise_rate": round(
            (noise_message_count / summary.messages_total) if summary.messages_total > 0 else 0.0,
            6,
        ),
        "pending_review_messages": pending_review_message_count,
        "pending_review_rate": round(
            (pending_review_message_count / summary.messages_total)
            if summary.messages_total > 0
            else 0.0,
            6,
        ),
    }
    legitimate_basis = _legitimate_basis(
        summary=summary,
        approved_senders=approved_senders,
        auto_approved_senders=auto_approved_sender_ips,
        excluded_noise_senders=noise_sender_ips,
    )
    legitimate_messages_total = int(legitimate_basis["messages_total"])
    legitimate_fail_count = int(legitimate_basis["fail_count"])
    legitimate_fail_rate = float(legitimate_basis["fail_rate"])
    legitimate_dkim_aligned_count = sum(
        summary.source_dkim_aligned_pass_counts.get(source_ip, 0)
        for source_ip in effective_approved_senders
    )
    legitimate_spf_aligned_count = sum(
        summary.source_spf_aligned_pass_counts.get(source_ip, 0)
        for source_ip in effective_approved_senders
    )
    legitimate_dkim_aligned_rate = (
        (legitimate_dkim_aligned_count / legitimate_messages_total)
        if legitimate_messages_total > 0
        else 0.0
    )
    legitimate_spf_aligned_rate = (
        (legitimate_spf_aligned_count / legitimate_messages_total)
        if legitimate_messages_total > 0
        else 0.0
    )
    authentication_coverage_rate = max(
        legitimate_dkim_aligned_rate,
        legitimate_spf_aligned_rate,
    )
    authentication_coverage_blended_rate = (
        (legitimate_dkim_aligned_rate + legitimate_spf_aligned_rate) / 2.0
    )
    protection_posture = _protection_posture_assessment(
        dominant_policy=dominant_policy,
        average_policy_pct=average_policy_pct,
        policy_consistency=policy_consistency,
    )
    attack_pressure = _attack_pressure_assessment(
        total_messages=summary.messages_total,
        total_fail_count=summary.dmarc_fail_count,
        legitimate_fail_count=legitimate_fail_count,
        noise_fail_count=noise_fail_count,
        policy=dominant_policy,
    )
    issues_output = _reframe_issues_for_attack_pressure(
        issues=summary.issues,
        dominant_policy=dominant_policy,
        legitimate_fail_rate=legitimate_fail_rate,
        attack_pressure=attack_pressure,
        messages_total=summary.messages_total,
    )
    deliverability_safety_score, deliverability_safety_breakdown = _deliverability_safety_score(
        dominant_policy=dominant_policy,
        average_policy_pct=average_policy_pct,
        legitimate_fail_rate=legitimate_fail_rate,
        legitimate_messages_total=legitimate_messages_total,
    )
    deliverability_safety_note = _deliverability_safety_note(
        legitimate_basis=legitimate_basis,
        noise_fail_count=noise_fail_count,
        total_fail_count=summary.dmarc_fail_count,
    )
    anti_spoofing_posture_score, anti_spoofing_posture_breakdown = _anti_spoofing_posture_score(
        dominant_policy=dominant_policy,
        average_policy_pct=average_policy_pct,
        fail_rate=fail_rate,
    )
    score_confidence = _score_confidence(summary.messages_total)
    readiness = _enforcement_readiness_assessment(
        dominant_policy=dominant_policy,
        average_policy_pct=average_policy_pct,
        legitimate_pass_rate=float(legitimate_basis["pass_rate"]),
        legitimate_messages_total=legitimate_messages_total,
        has_high_risk_findings=_has_high_risk_findings(issues_output),
        basis=str(legitimate_basis["basis"]),
    )
    enforcement_readiness = str(readiness["status"])
    readiness_detail = str(readiness["detail"])
    policy_impact = _policy_impact_simulation(
        dominant_policy=dominant_policy,
        average_policy_pct=average_policy_pct,
        messages_total=summary.messages_total,
        dmarc_fail_count=summary.dmarc_fail_count,
        quarantine_actions=summary.disposition_counts.get("quarantine", 0),
        reject_actions=reject_actions,
        legitimate_messages_total=legitimate_messages_total,
        legitimate_fail_count=legitimate_fail_count,
        basis=str(legitimate_basis["basis"]),
    )
    recommendations_output = [
        (
            f"[{item.get('severity', 'low')}/{item.get('category', 'general')}/"
            f"{item.get('confidence', 'low')}] {item.get('title', '')} "
            f"{item.get('evidence', '')}"
        ).strip()
        for item in issues_output[:4]
        if isinstance(item, dict)
    ]
    if not recommendations_output:
        recommendations_output = list(summary.recommendations)
    receiver_side_security_note = None
    if receiver_side_security_fail_count > 0:
        receiver_side_security_note = (
            "Some failing sources are likely recipient-side security relay/scan infrastructure "
            "(for example cloud-sec-av.com). These are excluded from safety-score penalties unless "
            "you verify they are in your own sender path."
        )
        recommendations_output.insert(
            0,
            (
                "Receiver-side relay signal detected in failing sources. "
                "Do not add these relay IPs to SPF; keep DKIM alignment strong and "
                "focus remediation on approved sender paths (such as M365 outbound)."
            ),
        )
    new_sender_count = sum(
        1 for source_ip, _ in sorted_senders if source_ip not in previous_sender_history
    )
    approved_sender_count = sum(
        1
        for source_ip, _ in sorted_senders
        if (
            source_ip in approved_senders
            or classified_sources.get(source_ip, {}).get("legit_status") == "approved"
        )
    )
    dns_diagnostics = _build_dns_diagnostics(
        summary.domain,
        top_dkim_selectors,
        resolve_dns_records=resolve_dns_records,
    )
    dns_action_hints = _build_dns_action_hints(summary.domain, dns_diagnostics)
    for hint in dns_action_hints:
        tagged_hint = f"[dns/configuration] {hint}"
        if tagged_hint not in recommendations_output:
            recommendations_output.insert(0, tagged_hint)
    m365_dkim_carrying_load = _is_m365_dkim_carrying_load(
        has_m365_senders=bool(m365_sender_ips),
        dns_diagnostics=dns_diagnostics,
        dkim_aligned_rate=dkim_rate,
        spf_alignment_gap_rate=spf_alignment_gap_rate,
        legitimate_fail_rate=legitimate_fail_rate,
    )
    legitimate_forwarding_related_count = sum(
        count
        for source_ip in effective_approved_senders
        for reason, count in summary.source_override_reason_counts.get(source_ip, {}).items()
        if reason in _FORWARDING_REASON_TYPES
    )
    _annotate_sender_inventory_labels(
        sender_inventory_items,
        m365_dkim_carrying_load=m365_dkim_carrying_load,
        dkim_rate=dkim_rate,
    )
    action_plan_output = _build_dynamic_action_plan(
        domain=summary.domain,
        dominant_policy=dominant_policy,
        sender_inventory=sender_inventory_items,
        default_action_plan=summary.action_plan,
        dns_diagnostics=dns_diagnostics,
        m365_alignment_sender=_select_m365_alignment_sender(
            source_fail_counts=summary.source_fail_counts,
            source_message_counts=summary.source_message_counts,
            classified_sources=classified_sources,
        ),
        dkim_aligned_rate=dkim_rate,
        spf_alignment_gap_rate=spf_alignment_gap_rate,
        legitimate_fail_rate=legitimate_fail_rate,
        m365_is_heavy=is_m365_heavy,
        m365_failing_messages=m365_fail_count,
        m365_dkim_carrying_load=m365_dkim_carrying_load,
        legitimate_dkim_failure_modes=_legitimate_dkim_failure_modes(
            source_ips=effective_approved_senders,
            missing_dkim_counts=summary.source_fail_missing_dkim_counts,
            dkim_auth_fail_counts=summary.source_fail_dkim_auth_fail_counts,
            dkim_unaligned_counts=summary.source_fail_dkim_unaligned_counts,
        ),
        legitimate_forwarding_related_count=legitimate_forwarding_related_count,
    )
    if dns_action_hints:
        merged_actions: list[str] = []
        for step in dns_action_hints + action_plan_output:
            if step not in merged_actions:
                merged_actions.append(step)
        action_plan_output = merged_actions

    approved_day_message_counts = _sum_day_counts_for_sources(
        summary.source_day_message_counts,
        effective_approved_senders,
    )
    noise_day_message_counts = _sum_day_counts_for_sources(
        summary.source_day_message_counts,
        noise_sender_ips,
    )
    approved_day_fail_counts = _sum_day_counts_for_sources(
        summary.source_day_fail_counts,
        effective_approved_senders,
    )
    noise_day_fail_counts = _sum_day_counts_for_sources(
        summary.source_day_fail_counts,
        noise_sender_ips,
    )
    basis_name = str(legitimate_basis.get("basis", "all_observed_traffic"))
    legitimate_day_message_counts, legitimate_day_fail_counts = _legitimate_day_basis_counts(
        basis=basis_name,
        messages_by_day=summary.messages_by_day,
        dmarc_fail_by_day=summary.dmarc_fail_by_day,
        noise_messages_by_day=noise_day_message_counts,
        noise_fail_by_day=noise_day_fail_counts,
        approved_messages_by_day=approved_day_message_counts,
        approved_fail_by_day=approved_day_fail_counts,
    )

    time_series = _build_daily_time_series(
        messages_by_day=summary.messages_by_day,
        dmarc_pass_by_day=summary.dmarc_pass_by_day,
        dmarc_fail_by_day=summary.dmarc_fail_by_day,
        dkim_aligned_pass_by_day=summary.dkim_aligned_pass_by_day,
        spf_aligned_pass_by_day=summary.spf_aligned_pass_by_day,
        approved_messages_by_day=approved_day_message_counts,
        noise_messages_by_day=noise_day_message_counts,
        approved_fail_by_day=approved_day_fail_counts,
        noise_fail_by_day=noise_day_fail_counts,
        legitimate_basis_messages_by_day=legitimate_day_message_counts,
        legitimate_basis_fail_by_day=legitimate_day_fail_counts,
    )

    return {
        "domain": summary.domain,
        "reports_seen": summary.reports_seen,
        "messages_total": summary.messages_total,
        "dmarc_pass_count": summary.dmarc_pass_count,
        "dmarc_fail_count": summary.dmarc_fail_count,
        "dmarc_pass_rate": round(pass_rate, 6),
        "dmarc_fail_rate": round(fail_rate, 6),
        "dkim_auth_pass_rate": round(dkim_auth_rate, 6),
        "dkim_aligned_pass_rate": round(dkim_rate, 6),
        "spf_auth_pass_rate": round(spf_auth_rate, 6),
        "spf_aligned_pass_rate": round(spf_rate, 6),
        "dkim_alignment_gap_rate": round(dkim_alignment_gap_rate, 6),
        "spf_alignment_gap_rate": round(spf_alignment_gap_rate, 6),
        "auth_breakdown": {
            "both_pass_rate": round(auth_both_pass_rate, 6),
            "dkim_only_pass_rate": round(auth_dkim_only_pass_rate, 6),
            "spf_only_pass_rate": round(auth_spf_only_pass_rate, 6),
            "neither_pass_rate": round(auth_neither_pass_rate, 6),
        },
        "disposition_counts": dict(sorted(summary.disposition_counts.items())),
        "published_policy_counts": dict(sorted(summary.policy_counts.items())),
        "dominant_policy": dominant_policy,
        "policy_consistency": round(policy_consistency, 6),
        "average_policy_pct": round(average_policy_pct, 2),
        "enforcement_observed_rate": round(enforcement_observed_rate, 6),
        "top_failing_source_share": round(top_source_share, 6),
        "health_score": health_score,
        "health_label": health_label,
        "historical_trend_score": health_score,
        "historical_trend_label": health_label,
        "historical_trend_score_title": "Historical Trend Score",
        "historical_trend_score_description": (
            "Historical Trend Score uses all observed traffic (including receiver-side noise) "
            "for long-term visibility. Deliverability Safety is the enforcement-risk metric."
        ),
        "aggregate_evidence_note": (
            "DMARC aggregate reports are record-level summaries, not message-level traces."
        ),
        "deliverability_safety_score": deliverability_safety_score,
        "anti_spoofing_posture_score": anti_spoofing_posture_score,
        "protection_posture_score": int(protection_posture["score"]),
        "protection_posture_grade": str(protection_posture["grade"]),
        "protection_posture_detail": str(protection_posture["detail"]),
        "authentication_coverage_rate": round(authentication_coverage_rate, 6),
        "authentication_coverage_blended_rate": round(authentication_coverage_blended_rate, 6),
        "authentication_coverage_dkim_rate": round(legitimate_dkim_aligned_rate, 6),
        "authentication_coverage_spf_rate": round(legitimate_spf_aligned_rate, 6),
        "attack_pressure_level": str(attack_pressure["level"]),
        "attack_pressure_label": str(attack_pressure["label"]),
        "attack_pressure_fail_count": int(attack_pressure["unauthorized_fail_count"]),
        "attack_pressure_fail_rate": round(float(attack_pressure["unauthorized_fail_rate"]), 6),
        "attack_pressure_note": str(attack_pressure["note"]),
        "score_confidence": score_confidence,
        "health_score_summary": (
            "Historical Trend Score uses all observed traffic and subtracts points for "
            "DMARC failures, weak aligned authentication coverage, and monitor-only policy posture."
        ),
        "health_score_breakdown": health_breakdown,
        "health_score_causes": health_causes,
        "deliverability_safety_breakdown": deliverability_safety_breakdown,
        "deliverability_safety_note": deliverability_safety_note,
        "anti_spoofing_posture_breakdown": anti_spoofing_posture_breakdown,
        "enforcement_readiness": enforcement_readiness,
        "enforcement_readiness_detail": readiness_detail,
        "readiness_gate": readiness,
        "policy_impact_simulation": policy_impact,
        "legitimate_basis": legitimate_basis,
        "sender_inventory_summary": sender_inventory_summary,
        "dns_diagnostics": dns_diagnostics,
        "is_m365_heavy": is_m365_heavy,
        "m365_message_count": m365_message_count,
        "m365_message_rate": round(m365_message_rate, 6),
        "m365_failing_messages": m365_fail_count,
        "m365_dkim_carrying_load": m365_dkim_carrying_load,
        "receiver_side_security_relay_fail_count": receiver_side_security_fail_count,
        "receiver_side_security_relay_fail_share": round(receiver_side_security_fail_share, 6),
        "receiver_side_security_relay_sources": receiver_side_security_sources,
        "receiver_side_security_relay_note": receiver_side_security_note,
        "noise_messages_excluded_from_safety": noise_message_count,
        "noise_failures_excluded_from_safety": noise_fail_count,
        "auto_approved_sender_count": len(auto_approved_sender_ips),
        "time_series": time_series,
        "time_series_days": len(time_series),
        "time_series_start": time_series[0]["date"] if time_series else "",
        "time_series_end": time_series[-1]["date"] if time_series else "",
        "evidence_overview": {
            "top_reporters": top_reporters,
            "top_override_reasons": top_override_reasons,
            "top_header_from": top_header_from,
            "top_envelope_from": top_envelope_from,
            "top_spf_alignment_gap_pairs": top_spf_alignment_gap_pairs,
            "top_dkim_selectors": top_dkim_selectors,
        },
        "sender_inventory": sender_inventory_items,
        "new_sender_count": new_sender_count,
        "approved_sender_count": approved_sender_count,
        "top_failing_sources": top_failing_source_items,
        "recommendations": recommendations_output,
        "issues": issues_output,
        "action_plan": action_plan_output,
    }
