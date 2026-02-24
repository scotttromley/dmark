"""Scoring, assessment, and readiness functions for DMARC domain summaries."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import DomainSummary


def _dominant_policy(policy_counts: dict[str, int]) -> tuple[str, float]:
    if not policy_counts:
        return "unknown", 0.0
    total = sum(policy_counts.values())
    policy, count = sorted(policy_counts.items(), key=lambda item: item[1], reverse=True)[0]
    consistency = (count / total) if total > 0 else 0.0
    return policy, consistency


def _health_score_and_breakdown(
    fail_rate: float,
    dkim_rate: float,
    spf_rate: float,
    dominant_policy: str,
) -> tuple[int, list[dict[str, object]]]:
    score = 100.0
    fail_penalty = min(50.0, fail_rate * 500.0)
    score -= fail_penalty
    auth_best = max(dkim_rate, spf_rate)
    auth_blend = (dkim_rate + spf_rate) / 2.0
    # DMARC passes if either aligned DKIM or SPF passes, so score uses best-path
    # coverage first, then lightly penalizes weak blended coverage.
    best_path_penalty = max(0.0, (0.95 - auth_best) * 200.0)
    blend_penalty = max(0.0, (0.85 - auth_blend) * 60.0)
    score -= best_path_penalty
    score -= blend_penalty
    monitor_mode_penalty = 0.0
    if dominant_policy == "none":
        monitor_mode_penalty = 5.0
        score -= monitor_mode_penalty
    score = max(0.0, min(100.0, score))
    breakdown = [
        {
            "factor": "DMARC fail rate",
            "points_lost": round(fail_penalty, 2),
            "detail": f"{fail_rate:.2%} of messages fail DMARC.",
        },
        {
            "factor": "Aligned auth best-path coverage",
            "points_lost": round(best_path_penalty, 2),
            "detail": (
                "Best aligned method coverage is "
                f"{auth_best:.2%} (target >= 95%)."
            ),
        },
        {
            "factor": "Aligned auth blended coverage",
            "points_lost": round(blend_penalty, 2),
            "detail": (
                "Combined DKIM/SPF aligned coverage is "
                f"{auth_blend:.2%} (target >= 85%)."
            ),
        },
        {
            "factor": "Policy posture",
            "points_lost": round(monitor_mode_penalty, 2),
            "detail": (
                "Monitor-only policy (p=none) carries small score penalty."
                if dominant_policy == "none"
                else "Domain is publishing an enforcing policy posture."
            ),
        },
    ]
    return int(round(score)), breakdown


def _health_score_causes(health_breakdown: list[dict[str, object]]) -> list[str]:
    ranked = sorted(
        health_breakdown,
        key=lambda item: float(item.get("points_lost", 0.0)),
        reverse=True,
    )
    causes: list[str] = []
    for item in ranked:
        points_lost = float(item.get("points_lost", 0.0))
        if points_lost <= 0:
            continue
        causes.append(
            (
                f"Historical trend score: {item.get('factor', 'factor')} cost "
                f"{points_lost:.1f} points: {item.get('detail', '')}"
            )
        )
        if len(causes) >= 3:
            break
    return causes


def _health_label(health_score: int) -> str:
    if health_score >= 95:
        return "excellent"
    if health_score >= 85:
        return "good"
    if health_score >= 70:
        return "fair"
    if health_score >= 50:
        return "poor"
    return "critical"


def _legitimate_basis(
    summary: DomainSummary,
    approved_senders: set[str],
    auto_approved_senders: set[str],
    excluded_noise_senders: set[str],
) -> dict[str, object]:
    tracked_approved_senders = set(approved_senders) | set(auto_approved_senders)
    noise_sources = set(excluded_noise_senders)
    observed_total = summary.messages_total
    noise_messages = sum(summary.source_message_counts.get(ip, 0) for ip in noise_sources)
    noise_pass = sum(summary.source_pass_counts.get(ip, 0) for ip in noise_sources)
    noise_fail = sum(summary.source_fail_counts.get(ip, 0) for ip in noise_sources)
    effective_total = max(0, observed_total - noise_messages)
    effective_pass = max(0, summary.dmarc_pass_count - noise_pass)
    effective_fail = max(0, summary.dmarc_fail_count - noise_fail)

    if summary.messages_total <= 0:
        return {
            "basis": "all_observed_traffic",
            "messages_total": 0,
            "pass_count": 0,
            "fail_count": 0,
            "pass_rate": 0.0,
            "fail_rate": 0.0,
            "coverage_rate": 0.0,
            "approved_senders_configured": len(approved_senders),
            "auto_approved_senders_detected": len(auto_approved_senders),
            "noise_messages_excluded": 0,
            "noise_failures_excluded": 0,
        }

    if not tracked_approved_senders:
        return {
            "basis": (
                "all_observed_non_noise_traffic"
                if noise_messages > 0
                else "all_observed_traffic"
            ),
            "messages_total": effective_total,
            "pass_count": effective_pass,
            "fail_count": effective_fail,
            "pass_rate": round((effective_pass / effective_total), 6) if effective_total > 0 else 0.0,
            "fail_rate": round((effective_fail / effective_total), 6) if effective_total > 0 else 0.0,
            "coverage_rate": 1.0,
            "approved_senders_configured": 0,
            "auto_approved_senders_detected": len(auto_approved_senders),
            "noise_messages_excluded": noise_messages,
            "noise_failures_excluded": noise_fail,
        }

    approved_messages = 0
    approved_pass = 0
    approved_fail = 0
    for source_ip in tracked_approved_senders:
        if source_ip in noise_sources:
            continue
        approved_messages += summary.source_message_counts.get(source_ip, 0)
        approved_pass += summary.source_pass_counts.get(source_ip, 0)
        approved_fail += summary.source_fail_counts.get(source_ip, 0)

    if approved_messages <= 0:
        return {
            "basis": "all_observed_non_noise_traffic_no_approved_sender_matches",
            "messages_total": effective_total,
            "pass_count": effective_pass,
            "fail_count": effective_fail,
            "pass_rate": round((effective_pass / effective_total), 6) if effective_total > 0 else 0.0,
            "fail_rate": round((effective_fail / effective_total), 6) if effective_total > 0 else 0.0,
            "coverage_rate": 1.0,
            "approved_senders_configured": len(approved_senders),
            "auto_approved_senders_detected": len(auto_approved_senders),
            "noise_messages_excluded": noise_messages,
            "noise_failures_excluded": noise_fail,
        }

    return {
        "basis": "approved_and_auto_approved_non_noise_senders",
        "messages_total": approved_messages,
        "pass_count": approved_pass,
        "fail_count": approved_fail,
        "pass_rate": round((approved_pass / approved_messages), 6),
        "fail_rate": round((approved_fail / approved_messages), 6),
        "coverage_rate": round((approved_messages / effective_total), 6) if effective_total > 0 else 0.0,
        "approved_senders_configured": len(approved_senders),
        "auto_approved_senders_detected": len(auto_approved_senders),
        "noise_messages_excluded": noise_messages,
        "noise_failures_excluded": noise_fail,
    }


def _deliverability_safety_score(
    dominant_policy: str,
    average_policy_pct: float,
    legitimate_fail_rate: float,
    legitimate_messages_total: int,
) -> tuple[int, list[dict[str, object]]]:
    score = 100.0
    fail_penalty = min(55.0, legitimate_fail_rate * 180.0)
    score -= fail_penalty
    enforcement_risk_penalty = 0.0
    if dominant_policy in {"quarantine", "reject"} and legitimate_fail_rate > 0.01:
        enforcement_risk_penalty = min(
            15.0,
            max(0.0, legitimate_fail_rate - 0.01) * 200.0,
        )
        score -= enforcement_risk_penalty
    sample_penalty = 0.0
    if legitimate_messages_total < 300:
        sample_penalty = 8.0
        score -= sample_penalty
    pct_penalty = 0.0
    if dominant_policy in {"quarantine", "reject"} and average_policy_pct < 100:
        pct_penalty = min(10.0, (100.0 - average_policy_pct) * 0.25)
        score -= pct_penalty
    score = max(0.0, min(100.0, score))
    breakdown = [
        {
            "factor": "Legitimate DMARC fail rate",
            "points_lost": round(fail_penalty, 2),
            "detail": (
                f"{legitimate_fail_rate:.2%} fail rate on traffic used for readiness."
            ),
        },
        {
            "factor": "Active enforcement risk",
            "points_lost": round(enforcement_risk_penalty, 2),
            "detail": (
                "Legitimate failures under enforcing policy increase deliverability risk."
                if enforcement_risk_penalty > 0
                else "No additional enforcing-policy delivery risk applied."
            ),
        },
        {
            "factor": "Sample confidence",
            "points_lost": round(sample_penalty, 2),
            "detail": (
                "Low message volume lowers confidence in safe-enforcement conclusions."
                if sample_penalty > 0
                else "Sufficient message volume for stable safety estimation."
            ),
        },
        {
            "factor": "Policy pct coverage",
            "points_lost": round(pct_penalty, 2),
            "detail": (
                f"Average policy pct is {average_policy_pct:.1f}, below 100."
                if pct_penalty > 0
                else "Policy pct coverage does not reduce safety score."
            ),
        },
    ]
    return int(round(score)), breakdown


def _deliverability_safety_note(
    legitimate_basis: dict[str, object],
    noise_fail_count: int,
    total_fail_count: int,
) -> str:
    basis_name = str(legitimate_basis.get("basis", "all_observed_traffic"))
    legitimate_fail_count = int(legitimate_basis.get("fail_count", 0))
    if total_fail_count <= 0:
        return "No DMARC failures were observed in this reporting window."
    if legitimate_fail_count <= 0:
        if noise_fail_count > 0:
            return (
                "No deliverability-safety penalty applied: observed failures are outside the "
                f"readiness basis ({basis_name}), including classified receiver-side/noise flows."
            )
        return (
            "No deliverability-safety penalty applied: observed failures are outside the "
            f"readiness basis ({basis_name}) and do not impact currently approved sender traffic."
        )
    legitimate_message_total = int(legitimate_basis.get("messages_total", 0))
    legitimate_fail_rate = (
        (legitimate_fail_count / legitimate_message_total)
        if legitimate_message_total > 0
        else 0.0
    )
    return (
        "Deliverability-safety penalties are based on the readiness basis "
        f"({basis_name}); current legitimate fail rate is {legitimate_fail_rate:.2%}."
    )


def _anti_spoofing_posture_score(
    dominant_policy: str,
    average_policy_pct: float,
    fail_rate: float,
) -> tuple[int, list[dict[str, object]]]:
    posture_base = {
        "none": 30.0,
        "quarantine": 70.0,
        "reject": 100.0,
    }.get(dominant_policy, 40.0)
    score = posture_base
    pct_penalty = 0.0
    if dominant_policy in {"quarantine", "reject"} and average_policy_pct < 100:
        pct_penalty = min(30.0, (100.0 - average_policy_pct) * 0.6)
        score -= pct_penalty
    monitor_penalty = 0.0
    if dominant_policy == "none":
        monitor_penalty = min(20.0, fail_rate * 300.0)
        score -= monitor_penalty
    score = max(0.0, min(100.0, score))
    breakdown = [
        {
            "factor": "Published policy posture",
            "points": round(posture_base, 2),
            "detail": f"Dominant policy is {dominant_policy}.",
        },
        {
            "factor": "Policy pct reduction",
            "points_lost": round(pct_penalty, 2),
            "detail": (
                f"Average policy pct is {average_policy_pct:.1f}, reducing spoof-blocking coverage."
                if pct_penalty > 0
                else "Policy pct does not reduce spoof-blocking coverage."
            ),
        },
        {
            "factor": "Monitor-mode exposure",
            "points_lost": round(monitor_penalty, 2),
            "detail": (
                "Monitor-only posture leaves failing traffic un-enforced."
                if monitor_penalty > 0
                else "No monitor-mode exposure penalty applied."
            ),
        },
    ]
    return int(round(score)), breakdown


def _has_high_risk_findings(issues: list[dict[str, object]]) -> bool:
    high_risk_categories = {
        "legitimate_misconfiguration",
        "alignment_gap",
        "enforcement_gap",
        "unauthorized_or_misconfigured_sources",
    }
    for item in issues:
        severity = str(item.get("severity", "")).lower()
        category = str(item.get("category", "")).lower()
        if severity in {"critical", "high"} and category in high_risk_categories:
            return True
    return False


def _enforcement_readiness_assessment(
    dominant_policy: str,
    average_policy_pct: float,
    legitimate_pass_rate: float,
    legitimate_messages_total: int,
    has_high_risk_findings: bool,
    basis: str,
) -> dict[str, object]:
    if legitimate_messages_total < 300:
        return {
            "status": "insufficient_data",
            "detail": (
                f"Only {legitimate_messages_total} messages in readiness basis "
                f"({basis}). Gather more data before policy changes."
            ),
            "basis": basis,
        }

    if dominant_policy == "none":
        if has_high_risk_findings:
            return {
                "status": "not_ready",
                "detail": "Resolve high-severity sender/authentication issues before moving to quarantine.",
                "basis": basis,
            }
        if legitimate_pass_rate >= 0.98:
            return {
                "status": "quarantine_ready",
                "detail": (
                    f"Legitimate pass rate is {legitimate_pass_rate:.2%} on basis {basis}; "
                    "domain is ready for staged quarantine rollout."
                ),
                "basis": basis,
            }
        if legitimate_pass_rate >= 0.95:
            return {
                "status": "close_to_quarantine",
                "detail": (
                    f"Legitimate pass rate is {legitimate_pass_rate:.2%} on basis {basis}; "
                    "fix remaining sources before quarantine."
                ),
                "basis": basis,
            }
        return {
            "status": "not_ready",
            "detail": (
                f"Legitimate pass rate is {legitimate_pass_rate:.2%} on basis {basis}; "
                "improve sender alignment first."
            ),
            "basis": basis,
        }

    if dominant_policy == "quarantine":
        if average_policy_pct < 100:
            return {
                "status": "stabilize_quarantine",
                "detail": (
                    f"Average pct is {average_policy_pct:.1f}. Increase pct toward 100 "
                    "before reject readiness decisions."
                ),
                "basis": basis,
            }
        if has_high_risk_findings:
            return {
                "status": "stabilize_quarantine",
                "detail": "Quarantine is active, but high-risk findings remain unresolved.",
                "basis": basis,
            }
        if legitimate_pass_rate >= 0.99:
            return {
                "status": "reject_ready",
                "detail": (
                    f"Legitimate pass rate is {legitimate_pass_rate:.2%} on basis {basis}; "
                    "domain appears ready for reject."
                ),
                "basis": basis,
            }
        return {
            "status": "stabilize_quarantine",
            "detail": (
                f"Legitimate pass rate is {legitimate_pass_rate:.2%} on basis {basis}; "
                "continue stabilizing before reject."
            ),
            "basis": basis,
        }

    if dominant_policy == "reject":
        if has_high_risk_findings:
            return {
                "status": "already_enforcing_with_risk",
                "detail": "Reject is active, but high-severity findings indicate potential delivery risk.",
                "basis": basis,
            }
        return {
            "status": "already_enforcing",
            "detail": "Reject policy is active and no high-severity readiness blockers were detected.",
            "basis": basis,
        }

    return {
        "status": "unknown",
        "detail": "Policy posture is unclear; verify published DMARC record state.",
        "basis": basis,
    }


def _score_confidence(messages_total: int) -> str:
    if messages_total >= 2000:
        return "high"
    if messages_total >= 500:
        return "medium"
    return "low"


def _policy_impact_simulation(
    dominant_policy: str,
    average_policy_pct: float,
    messages_total: int,
    dmarc_fail_count: int,
    quarantine_actions: int,
    reject_actions: int,
    legitimate_messages_total: int,
    legitimate_fail_count: int,
    basis: str,
) -> dict[str, object]:
    fail_rate = (dmarc_fail_count / messages_total) if messages_total > 0 else 0.0
    legitimate_fail_rate = (
        (legitimate_fail_count / legitimate_messages_total)
        if legitimate_messages_total > 0
        else 0.0
    )
    currently_enforced = quarantine_actions + reject_actions
    if dmarc_fail_count > 0:
        legitimate_currently_enforced = int(
            round((currently_enforced / dmarc_fail_count) * legitimate_fail_count)
        )
        reject_legitimate_currently_enforced = int(
            round((reject_actions / dmarc_fail_count) * legitimate_fail_count)
        )
    else:
        legitimate_currently_enforced = 0
        reject_legitimate_currently_enforced = 0
    confidence = _score_confidence(messages_total)

    def scenario(
        target: str,
        current_covered_total: int,
        current_covered_legitimate: int,
    ) -> dict[str, object]:
        additional = max(0, dmarc_fail_count - current_covered_total)
        legitimate_additional = max(0, legitimate_fail_count - current_covered_legitimate)
        return {
            "target_policy": target,
            "estimated_impacted_messages": dmarc_fail_count,
            "estimated_impacted_rate": round(fail_rate, 6),
            "estimated_additional_impacted_messages": additional,
            "estimated_additional_impacted_rate": round(
                (additional / messages_total) if messages_total > 0 else 0.0,
                6,
            ),
            "estimated_legitimate_impacted_messages": legitimate_fail_count,
            "estimated_legitimate_impacted_rate": round(legitimate_fail_rate, 6),
            "estimated_legitimate_additional_impacted_messages": legitimate_additional,
            "estimated_legitimate_additional_impacted_rate": round(
                (legitimate_additional / legitimate_messages_total)
                if legitimate_messages_total > 0
                else 0.0,
                6,
            ),
            "confidence": confidence,
        }

    return {
        "assumptions": [
            "Projection treats DMARC-failing volume as potentially affected under enforcing policy.",
            "Actual mailbox outcomes vary by receiver local policy and forwarding behavior.",
        ],
        "basis": basis,
        "current_policy": {
            "dominant_policy": dominant_policy,
            "average_policy_pct": round(average_policy_pct, 2),
            "currently_enforced_failures": currently_enforced,
            "currently_enforced_failures_rate": round(
                (currently_enforced / messages_total) if messages_total > 0 else 0.0,
                6,
            ),
            "currently_enforced_legitimate_failures": legitimate_currently_enforced,
            "currently_enforced_legitimate_failures_rate": round(
                (legitimate_currently_enforced / legitimate_messages_total)
                if legitimate_messages_total > 0
                else 0.0,
                6,
            ),
        },
        "quarantine_100": scenario(
            "quarantine",
            current_covered_total=currently_enforced,
            current_covered_legitimate=legitimate_currently_enforced,
        ),
        "reject_100": scenario(
            "reject",
            current_covered_total=reject_actions,
            current_covered_legitimate=reject_legitimate_currently_enforced,
        ),
    }


def _protection_posture_assessment(
    dominant_policy: str,
    average_policy_pct: float,
    policy_consistency: float,
) -> dict[str, object]:
    base_score = {
        "reject": 100.0,
        "quarantine": 80.0,
        "none": 35.0,
    }.get(dominant_policy, 45.0)
    pct_penalty = 0.0
    if dominant_policy in {"reject", "quarantine"} and average_policy_pct < 100:
        pct_penalty = min(20.0, (100.0 - average_policy_pct) * 0.5)
    consistency_penalty = 0.0
    if policy_consistency < 0.9:
        consistency_penalty = min(15.0, (0.9 - policy_consistency) * 50.0)
    score = max(0.0, min(100.0, base_score - pct_penalty - consistency_penalty))
    if score >= 97:
        grade = "A+"
    elif score >= 92:
        grade = "A"
    elif score >= 85:
        grade = "B"
    elif score >= 75:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return {
        "score": int(round(score)),
        "grade": grade,
        "detail": (
            f"Policy {dominant_policy} at average pct {average_policy_pct:.0f} "
            f"(consistency {policy_consistency:.0%})."
        ),
    }


def _attack_pressure_assessment(
    total_messages: int,
    total_fail_count: int,
    legitimate_fail_count: int,
    noise_fail_count: int,
    policy: str,
) -> dict[str, object]:
    unauthorized_fail_count = max(0, total_fail_count - legitimate_fail_count - noise_fail_count)
    unauthorized_fail_rate = (
        (unauthorized_fail_count / total_messages) if total_messages > 0 else 0.0
    )
    if unauthorized_fail_count == 0:
        level = "none"
        label = "None"
    elif unauthorized_fail_rate >= 0.05 or unauthorized_fail_count >= 2000:
        level = "high"
        label = "High"
    elif unauthorized_fail_rate >= 0.015 or unauthorized_fail_count >= 300:
        level = "medium"
        label = "Medium"
    else:
        level = "low"
        label = "Low"
    note = (
        "Unauthorized/pending-review DMARC failures are being blocked by enforcing policy."
        if policy in {"reject", "quarantine"} and unauthorized_fail_count > 0
        else "Attack pressure reflects unauthorized DMARC failures outside approved sender traffic."
    )
    return {
        "unauthorized_fail_count": unauthorized_fail_count,
        "unauthorized_fail_rate": unauthorized_fail_rate,
        "level": level,
        "label": label,
        "note": note,
    }


def _reframe_issues_for_attack_pressure(
    issues: list[dict[str, object]],
    dominant_policy: str,
    legitimate_fail_rate: float,
    attack_pressure: dict[str, object],
    messages_total: int,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    unauthorized_rate = float(attack_pressure.get("unauthorized_fail_rate", 0.0))
    unauthorized_count = int(attack_pressure.get("unauthorized_fail_count", 0))
    for item in issues:
        if not isinstance(item, dict):
            continue
        clone = dict(item)
        issue_id = str(clone.get("id", ""))
        if (
            dominant_policy in {"reject", "quarantine"}
            and issue_id in {"high_dmarc_fail_rate", "elevated_dmarc_fail_rate"}
            and legitimate_fail_rate <= 0.02
            and unauthorized_count > 0
        ):
            clone["category"] = "attack_pressure"
            clone["severity"] = (
                "medium" if unauthorized_rate >= 0.03 else "low"
            )
            clone["title"] = "Attack pressure is elevated, but enforcing policy is active."
            clone["evidence"] = (
                f"{unauthorized_rate:.2%} ({unauthorized_count} of {messages_total}) "
                "DMARC failures are outside approved sender traffic."
            )
            clone["likely_cause"] = (
                "Unauthorized or unapproved sender attempts are failing DMARC as expected under enforcement."
            )
            clone["actions"] = [
                "Review pending-review senders and mark known vendors as approved where appropriate.",
                "Keep enforcing policy in place; this traffic is expected to fail when unauthorized.",
            ]
        result.append(clone)
    return result
