from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache

try:
    import dns.resolver as _dns_resolver  # type: ignore
except Exception:
    _dns_resolver = None

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


@dataclass(frozen=True)
class AuthResult:
    domain: str
    result: str
    selector: str = ""


@dataclass(frozen=True)
class DmarcRecord:
    source_ip: str
    count: int
    disposition: str
    header_from: str
    envelope_from: str = ""
    override_reasons: tuple[str, ...] = ()
    dkim_results: tuple[AuthResult, ...] = ()
    spf_results: tuple[AuthResult, ...] = ()


@dataclass(frozen=True)
class DmarcReport:
    source_name: str
    org_name: str
    report_id: str
    date_begin: int
    date_end: int
    policy_domain: str
    adkim: str
    aspf: str
    policy_p: str
    policy_sp: str
    policy_pct: int
    records: tuple[DmarcRecord, ...] = ()

    @property
    def dedupe_key(self) -> tuple[str, str, int, int, str]:
        return (
            self.org_name.lower(),
            self.report_id,
            self.date_begin,
            self.date_end,
            self.policy_domain.lower(),
        )


@dataclass
class DomainSummary:
    domain: str
    reports_seen: int = 0
    messages_total: int = 0
    dmarc_pass_count: int = 0
    dmarc_fail_count: int = 0
    dkim_auth_pass_count: int = 0
    spf_auth_pass_count: int = 0
    dkim_aligned_pass_count: int = 0
    spf_aligned_pass_count: int = 0
    auth_both_pass_count: int = 0
    auth_dkim_only_pass_count: int = 0
    auth_spf_only_pass_count: int = 0
    auth_neither_pass_count: int = 0
    dkim_alignment_gap_count: int = 0
    spf_alignment_gap_count: int = 0
    disposition_counts: dict[str, int] = field(default_factory=dict)
    policy_counts: dict[str, int] = field(default_factory=dict)
    reporter_counts: dict[str, int] = field(default_factory=dict)
    override_reason_counts: dict[str, int] = field(default_factory=dict)
    source_message_counts: dict[str, int] = field(default_factory=dict)
    source_pass_counts: dict[str, int] = field(default_factory=dict)
    source_fail_counts: dict[str, int] = field(default_factory=dict)
    source_dkim_aligned_pass_counts: dict[str, int] = field(default_factory=dict)
    source_spf_aligned_pass_counts: dict[str, int] = field(default_factory=dict)
    header_from_counts: dict[str, int] = field(default_factory=dict)
    envelope_from_counts: dict[str, int] = field(default_factory=dict)
    source_header_from_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_envelope_from_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_disposition_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_override_reason_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_dkim_selector_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_dkim_domain_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_dkim_result_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_spf_domain_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_spf_result_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_day_message_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_day_fail_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    source_fail_missing_dkim_counts: dict[str, int] = field(default_factory=dict)
    source_fail_dkim_auth_fail_counts: dict[str, int] = field(default_factory=dict)
    source_fail_dkim_unaligned_counts: dict[str, int] = field(default_factory=dict)
    spf_alignment_gap_pair_counts: dict[str, int] = field(default_factory=dict)
    messages_by_day: dict[str, int] = field(default_factory=dict)
    dmarc_pass_by_day: dict[str, int] = field(default_factory=dict)
    dmarc_fail_by_day: dict[str, int] = field(default_factory=dict)
    dkim_aligned_pass_by_day: dict[str, int] = field(default_factory=dict)
    spf_aligned_pass_by_day: dict[str, int] = field(default_factory=dict)
    failing_source_counts: dict[str, int] = field(default_factory=dict)
    dkim_alignment_gap_source_counts: dict[str, int] = field(default_factory=dict)
    spf_alignment_gap_source_counts: dict[str, int] = field(default_factory=dict)
    dkim_selector_counts: dict[str, int] = field(default_factory=dict)
    policy_pct_total: int = 0
    policy_pct_reports: int = 0
    recommendations: list[str] = field(default_factory=list)
    issues: list[dict[str, object]] = field(default_factory=list)
    action_plan: list[str] = field(default_factory=list)

    def to_dict(
        self,
        resolve_source_ips: bool = False,
        resolve_dns_records: bool = False,
        previous_sender_history: set[str] | None = None,
        approved_senders: set[str] | None = None,
    ) -> dict[str, object]:
        previous_sender_history = previous_sender_history or set()
        approved_senders = approved_senders or set()
        pass_rate = (
            (self.dmarc_pass_count / self.messages_total) if self.messages_total else 0.0
        )
        fail_rate = (
            (self.dmarc_fail_count / self.messages_total) if self.messages_total else 0.0
        )
        dkim_rate = (
            (self.dkim_aligned_pass_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        dkim_auth_rate = (
            (self.dkim_auth_pass_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        spf_rate = (
            (self.spf_aligned_pass_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        spf_auth_rate = (
            (self.spf_auth_pass_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        dkim_alignment_gap_rate = (
            (self.dkim_alignment_gap_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        spf_alignment_gap_rate = (
            (self.spf_alignment_gap_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        auth_both_pass_rate = (
            (self.auth_both_pass_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        auth_dkim_only_pass_rate = (
            (self.auth_dkim_only_pass_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        auth_spf_only_pass_rate = (
            (self.auth_spf_only_pass_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        auth_neither_pass_rate = (
            (self.auth_neither_pass_count / self.messages_total)
            if self.messages_total
            else 0.0
        )
        average_policy_pct = (
            (self.policy_pct_total / self.policy_pct_reports)
            if self.policy_pct_reports > 0
            else 100.0
        )

        top_failing_sources = sorted(
            self.failing_source_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:10]
        dominant_policy, policy_consistency = _dominant_policy(self.policy_counts)
        top_source_share = 0.0
        if self.dmarc_fail_count > 0 and top_failing_sources:
            top_source_share = top_failing_sources[0][1] / self.dmarc_fail_count
        enforcement_actions = self.disposition_counts.get("quarantine", 0) + self.disposition_counts.get(
            "reject", 0
        )
        reject_actions = self.disposition_counts.get("reject", 0)
        enforcement_observed_rate = (
            (enforcement_actions / self.messages_total) if self.messages_total else 0.0
        )
        health_score, health_breakdown = _health_score_and_breakdown(
            fail_rate=fail_rate,
            dkim_rate=dkim_rate,
            spf_rate=spf_rate,
            dominant_policy=dominant_policy,
        )
        health_label = _health_label(health_score)
        health_causes = _health_score_causes(health_breakdown)

        top_reporters = _top_items(self.reporter_counts, limit=5, value_key="report_count")
        top_override_reasons = _top_items(
            self.override_reason_counts,
            limit=5,
            value_key="message_count",
        )
        top_header_from = _top_items(self.header_from_counts, limit=5, value_key="message_count")
        top_envelope_from = _top_items(
            self.envelope_from_counts,
            limit=5,
            value_key="message_count",
        )
        top_spf_alignment_gap_pairs = _top_items(
            self.spf_alignment_gap_pair_counts,
            limit=5,
            value_key="message_count",
        )
        top_dkim_selectors = _top_items(
            self.dkim_selector_counts,
            limit=5,
            value_key="message_count",
        )

        top_failing_source_items: list[dict[str, object]] = []
        receiver_side_security_sources: list[dict[str, object]] = []
        resolved_hostnames: dict[str, str | None] = {}
        classified_sources: dict[str, dict[str, str]] = {}
        auto_approved_sender_ips: set[str] = set()
        noise_sender_ips: set[str] = set()
        forwarding_reason_types = {
            "forwarded",
            "trusted_forwarder",
            "mailing_list",
            "local_policy",
        }
        sorted_senders = sorted(
            self.source_message_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )
        dynamic_min_auto_approve_volume = _dynamic_auto_approve_min_volume(
            self.messages_total
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
                hostname = _reverse_dns(source_ip)
                resolved_hostnames[source_ip] = hostname
            sender_total = self.source_message_counts.get(source_ip, count)
            sender_pass = self.source_pass_counts.get(source_ip, 0)
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
            source_override_counts = self.source_override_reason_counts.get(source_ip, {})
            source_forwarding_override_count = sum(
                count
                for reason, count in source_override_counts.items()
                if reason in forwarding_reason_types
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
                missing_dkim_counts=self.source_fail_missing_dkim_counts,
                dkim_auth_fail_counts=self.source_fail_dkim_auth_fail_counts,
                dkim_unaligned_counts=self.source_fail_dkim_unaligned_counts,
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
                        (count / self.dmarc_fail_count) if self.dmarc_fail_count > 0 else 0.0,
                        6,
                    ),
                    "evidence_details": {
                        "top_header_from": _top_items_for_source(
                            self.source_header_from_counts,
                            source_ip,
                            limit=3,
                        ),
                        "top_envelope_from": _top_items_for_source(
                            self.source_envelope_from_counts,
                            source_ip,
                            limit=3,
                        ),
                        "top_dispositions": _top_items_for_source(
                            self.source_disposition_counts,
                            source_ip,
                            limit=3,
                        ),
                        "top_override_reasons": _top_items_for_source(
                            self.source_override_reason_counts,
                            source_ip,
                            limit=3,
                        ),
                        "top_dkim_selectors": _top_items_for_source(
                            self.source_dkim_selector_counts,
                            source_ip,
                            limit=3,
                        ),
                        "top_dkim_domains": _top_items_for_source(
                            self.source_dkim_domain_counts,
                            source_ip,
                            limit=3,
                        ),
                        "top_dkim_results": _top_items_for_source(
                            self.source_dkim_result_counts,
                            source_ip,
                            limit=3,
                        ),
                        "top_spf_domains": _top_items_for_source(
                            self.source_spf_domain_counts,
                            source_ip,
                            limit=3,
                        ),
                        "top_spf_results": _top_items_for_source(
                            self.source_spf_result_counts,
                            source_ip,
                            limit=3,
                        ),
                        "aggregate_record_notice": (
                            "DMARC aggregate reports provide record-level buckets, not individual email events."
                        ),
                    },
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

        sender_inventory_items: list[dict[str, object]] = []
        for source_ip, count in sorted_senders[:20]:
            sender_fail = self.source_fail_counts.get(source_ip, 0)
            sender_pass = self.source_pass_counts.get(source_ip, 0)
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
                    "message_share_rate": round((count / self.messages_total), 6)
                    if self.messages_total > 0
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
            sender_pass = self.source_pass_counts.get(source_ip, 0)
            sender_pass_rate = (sender_pass / count) if count > 0 else 0.0
            classify_sender(
                source_ip=source_ip,
                sender_count=count,
                sender_pass_rate=sender_pass_rate,
            )

        receiver_side_security_fail_count = sum(
            self.source_fail_counts.get(source_ip, 0)
            for source_ip in noise_sender_ips
            if classified_sources.get(source_ip, {}).get("category") == "receiver_security_relay"
        )
        receiver_side_security_fail_share = (
            (receiver_side_security_fail_count / self.dmarc_fail_count)
            if self.dmarc_fail_count > 0
            else 0.0
        )
        noise_message_count = sum(
            self.source_message_counts.get(source_ip, 0) for source_ip in noise_sender_ips
        )
        noise_fail_count = sum(
            self.source_fail_counts.get(source_ip, 0) for source_ip in noise_sender_ips
        )
        m365_sender_ips = {
            source_ip
            for source_ip, classification in classified_sources.items()
            if classification.get("category") == "esp_microsoft365_outbound"
        }
        m365_message_count = sum(
            self.source_message_counts.get(source_ip, 0) for source_ip in m365_sender_ips
        )
        m365_fail_count = sum(
            self.source_fail_counts.get(source_ip, 0) for source_ip in m365_sender_ips
        )
        m365_message_rate = (
            (m365_message_count / self.messages_total) if self.messages_total > 0 else 0.0
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
            self.source_message_counts.get(source_ip, 0) for source_ip in effective_approved_senders
        )
        pending_review_message_count = max(
            0,
            self.messages_total - approved_message_count - noise_message_count,
        )
        sender_inventory_summary = {
            "approved_messages": approved_message_count,
            "approved_rate": round(
                (approved_message_count / self.messages_total) if self.messages_total > 0 else 0.0,
                6,
            ),
            "noise_messages": noise_message_count,
            "noise_rate": round(
                (noise_message_count / self.messages_total) if self.messages_total > 0 else 0.0,
                6,
            ),
            "pending_review_messages": pending_review_message_count,
            "pending_review_rate": round(
                (pending_review_message_count / self.messages_total)
                if self.messages_total > 0
                else 0.0,
                6,
            ),
        }
        legitimate_basis = _legitimate_basis(
            summary=self,
            approved_senders=approved_senders,
            auto_approved_senders=auto_approved_sender_ips,
            excluded_noise_senders=noise_sender_ips,
        )
        legitimate_messages_total = int(legitimate_basis["messages_total"])
        legitimate_fail_count = int(legitimate_basis["fail_count"])
        legitimate_fail_rate = float(legitimate_basis["fail_rate"])
        legitimate_dkim_aligned_count = sum(
            self.source_dkim_aligned_pass_counts.get(source_ip, 0)
            for source_ip in effective_approved_senders
        )
        legitimate_spf_aligned_count = sum(
            self.source_spf_aligned_pass_counts.get(source_ip, 0)
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
            total_messages=self.messages_total,
            total_fail_count=self.dmarc_fail_count,
            legitimate_fail_count=legitimate_fail_count,
            noise_fail_count=noise_fail_count,
            policy=dominant_policy,
        )
        issues_output = _reframe_issues_for_attack_pressure(
            issues=self.issues,
            dominant_policy=dominant_policy,
            legitimate_fail_rate=legitimate_fail_rate,
            attack_pressure=attack_pressure,
            messages_total=self.messages_total,
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
            total_fail_count=self.dmarc_fail_count,
        )
        anti_spoofing_posture_score, anti_spoofing_posture_breakdown = _anti_spoofing_posture_score(
            dominant_policy=dominant_policy,
            average_policy_pct=average_policy_pct,
            fail_rate=fail_rate,
        )
        score_confidence = _score_confidence(self.messages_total)
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
            messages_total=self.messages_total,
            dmarc_fail_count=self.dmarc_fail_count,
            quarantine_actions=self.disposition_counts.get("quarantine", 0),
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
            recommendations_output = list(self.recommendations)
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
        observed_selectors = [str(item.get("name", "")) for item in top_dkim_selectors]
        dns_diagnostics = (
            _resolve_domain_dns_diagnostics(self.domain, observed_selectors)
            if resolve_dns_records
            else {
                "enabled": False,
                "reason": "DNS diagnostics disabled for this run.",
                "domain": self.domain,
            }
        )
        dns_action_hints: list[str] = []
        if dns_diagnostics.get("enabled"):
            if not dns_diagnostics.get("dmarc_record_found"):
                dns_action_hints.append(
                    f"DNS check could not confirm a DMARC TXT record at _dmarc.{self.domain}. Verify the live record."
                )
            if not dns_diagnostics.get("spf_record_found"):
                dns_action_hints.append(
                    f"DNS check could not confirm an SPF TXT record at {self.domain}. Verify envelope domains and SPF publication."
                )
            if dns_diagnostics.get("m365_dkim_status") == "partial":
                dns_action_hints.append(
                    "Only one of selector1/selector2 appears to target M365 DKIM. Publish both selectors before enabling DKIM."
                )
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
            for reason, count in self.source_override_reason_counts.get(source_ip, {}).items()
            if reason in forwarding_reason_types
        )
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
        action_plan_output = _build_dynamic_action_plan(
            domain=self.domain,
            dominant_policy=dominant_policy,
            sender_inventory=sender_inventory_items,
            default_action_plan=self.action_plan,
            dns_diagnostics=dns_diagnostics,
            m365_alignment_sender=_select_m365_alignment_sender(
                source_fail_counts=self.source_fail_counts,
                source_message_counts=self.source_message_counts,
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
                missing_dkim_counts=self.source_fail_missing_dkim_counts,
                dkim_auth_fail_counts=self.source_fail_dkim_auth_fail_counts,
                dkim_unaligned_counts=self.source_fail_dkim_unaligned_counts,
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
            self.source_day_message_counts,
            effective_approved_senders,
        )
        noise_day_message_counts = _sum_day_counts_for_sources(
            self.source_day_message_counts,
            noise_sender_ips,
        )
        approved_day_fail_counts = _sum_day_counts_for_sources(
            self.source_day_fail_counts,
            effective_approved_senders,
        )
        noise_day_fail_counts = _sum_day_counts_for_sources(
            self.source_day_fail_counts,
            noise_sender_ips,
        )

        time_series = _build_daily_time_series(
            messages_by_day=self.messages_by_day,
            dmarc_pass_by_day=self.dmarc_pass_by_day,
            dmarc_fail_by_day=self.dmarc_fail_by_day,
            dkim_aligned_pass_by_day=self.dkim_aligned_pass_by_day,
            spf_aligned_pass_by_day=self.spf_aligned_pass_by_day,
            approved_messages_by_day=approved_day_message_counts,
            noise_messages_by_day=noise_day_message_counts,
            approved_fail_by_day=approved_day_fail_counts,
            noise_fail_by_day=noise_day_fail_counts,
        )

        return {
            "domain": self.domain,
            "reports_seen": self.reports_seen,
            "messages_total": self.messages_total,
            "dmarc_pass_count": self.dmarc_pass_count,
            "dmarc_fail_count": self.dmarc_fail_count,
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
            "disposition_counts": dict(sorted(self.disposition_counts.items())),
            "published_policy_counts": dict(sorted(self.policy_counts.items())),
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
) -> list[dict[str, object]]:
    approved_messages_by_day = approved_messages_by_day or {}
    noise_messages_by_day = noise_messages_by_day or {}
    approved_fail_by_day = approved_fail_by_day or {}
    noise_fail_by_day = noise_fail_by_day or {}
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
        legitimate_fail = int(approved_fail_by_day.get(day, 0))
        noise_fail = int(noise_fail_by_day.get(day, 0))
        attack_fail = max(0, dmarc_fail - legitimate_fail - noise_fail)
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
                "legitimate_fail_count": legitimate_fail,
                "attack_pressure_fail_count": attack_fail,
                "legitimate_fail_rate": round(
                    (legitimate_fail / approved_messages) if approved_messages > 0 else 0.0,
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


def _build_dynamic_action_plan(
    domain: str,
    dominant_policy: str,
    sender_inventory: list[dict[str, object]],
    default_action_plan: list[str],
    dns_diagnostics: dict[str, object] | None = None,
    m365_alignment_sender: dict[str, object] | None = None,
    dkim_aligned_rate: float = 0.0,
    spf_alignment_gap_rate: float = 0.0,
    legitimate_fail_rate: float = 0.0,
    m365_is_heavy: bool = False,
    m365_failing_messages: int = 0,
    m365_dkim_carrying_load: bool = False,
    legitimate_dkim_failure_modes: dict[str, int] | None = None,
    legitimate_forwarding_related_count: int = 0,
) -> list[str]:
    dns_diagnostics = dns_diagnostics or {}
    m365_present = any(
        isinstance(sender, dict)
        and sender.get("classification") == "esp_microsoft365_outbound"
        for sender in sender_inventory
    )
    legitimate_dkim_failure_modes = legitimate_dkim_failure_modes or {}
    if not m365_is_heavy and m365_present and m365_failing_messages <= 0:
        # Fallback for callers that don't precompute these values.
        m365_failing_messages = sum(
            int(sender.get("dmarc_fail_count", 0))
            for sender in sender_inventory
            if isinstance(sender, dict)
            and sender.get("classification") == "esp_microsoft365_outbound"
        )
    m365_safe_banner = bool(m365_is_heavy and m365_dkim_carrying_load)
    m365_spf_gap_expected = bool(
        m365_present
        and dns_diagnostics.get("m365_dkim_status") == "configured"
        and dkim_aligned_rate >= 0.90
        and spf_alignment_gap_rate >= 0.05
    )
    filtered_default_plan = (
        _filter_m365_spf_low_value_steps(default_action_plan)
        if m365_spf_gap_expected
        else list(default_action_plan)
    )
    selected_sender = m365_alignment_sender
    if selected_sender is None:
        for sender in sender_inventory:
            if not isinstance(sender, dict):
                continue
            if sender.get("classification") != "esp_microsoft365_outbound":
                continue
            if sender.get("suggested_action") != "fix_alignment":
                continue
            if int(sender.get("dmarc_fail_count", 0)) <= 0:
                continue
            selected_sender = sender
            break

    if selected_sender is None:
        if not m365_spf_gap_expected:
            return filtered_default_plan
        if m365_safe_banner:
            celebratory_plan = [
                "Authentication status: excellent (p=reject appears safe).",
                (
                    "Microsoft 365 sender paths account for "
                    f"{m365_failing_messages} failing messages in this window."
                ),
                "DKIM status: Microsoft 365 DKIM is configured, authenticated, and valid.",
                (
                    "SPF alignment lag is normal Microsoft 365 envelope-from behavior "
                    "(protection.outlook.com/onmicrosoft.com)."
                ),
                (
                    "DMARC uses aligned SPF OR aligned DKIM. Current DKIM alignment "
                    f"({dkim_aligned_rate:.2%}) is carrying legitimate authentication."
                ),
                "No action required on the SPF gap at this time.",
                (
                    "Do not add receiver relay/scanner hosts (for example cloud-sec-av.com) "
                    "to SPF unless they are confirmed sender paths."
                ),
                "Optional: continue monitoring for 30 days, then consider BIMI readiness.",
            ]
            return _merge_unique_steps(
                celebratory_plan,
                _append_legitimate_dkim_triage_steps(
                    filtered_default_plan,
                    legitimate_dkim_failure_modes,
                    legitimate_forwarding_related_count,
                ),
            )
        reassuring_plan = [
            "DKIM status: Microsoft 365 DKIM is configured and selector records are present.",
            (
                "SPF alignment gap is a common Microsoft 365 envelope-from behavior "
                "(onmicrosoft.com/protection.outlook.com return paths)."
            ),
            (
                "DMARC uses aligned SPF OR aligned DKIM; strong DKIM alignment is currently carrying "
                "authentication for most legitimate traffic."
            ),
        ]
        if legitimate_fail_rate <= 0.02:
            reassuring_plan.append(
                (
                    "No urgent SPF realignment is required while legitimate DMARC fail rate stays low "
                    f"({legitimate_fail_rate:.2%})."
                )
            )
        else:
            reassuring_plan.append(
                (
                    f"Legitimate DMARC fail rate is {legitimate_fail_rate:.2%}; investigate remaining "
                    "failing sender paths before changing SPF policy."
                )
            )
        return _merge_unique_steps(
            reassuring_plan,
            _append_legitimate_dkim_triage_steps(
                filtered_default_plan,
                legitimate_dkim_failure_modes,
                legitimate_forwarding_related_count,
            ),
        )

    routing_domain = (domain or "").replace(".", "-")
    selector_checks = dns_diagnostics.get("dkim_selector_checks", {})
    selector1_status = None
    selector2_status = None
    if isinstance(selector_checks, dict):
        selector1_status = selector_checks.get("selector1")
        selector2_status = selector_checks.get("selector2")
    selector1_cname = (
        selector1_status.get("cname")
        if isinstance(selector1_status, dict)
        else None
    )
    selector2_cname = (
        selector2_status.get("cname")
        if isinstance(selector2_status, dict)
        else None
    )
    m365_dkim_ready = bool(
        selector1_cname and selector2_cname
    )
    dynamic_plan: list[str] = []
    if dominant_policy == "reject" and not m365_spf_gap_expected:
        dynamic_plan.append(
            "CRITICAL: Domain is enforcing p=reject. Fix Microsoft 365 alignment promptly to reduce delivery risk."
        )

    if m365_safe_banner:
        dynamic_plan.extend(
            [
                "Authentication status: excellent (p=reject appears safe).",
                (
                    "Microsoft 365 sender paths account for "
                    f"{m365_failing_messages} failing messages in this window."
                ),
                "DKIM status: Microsoft 365 DKIM is configured, authenticated, and valid.",
                (
                    "SPF alignment lag is normal Microsoft 365 envelope-from behavior "
                    "(protection.outlook.com/onmicrosoft.com)."
                ),
                (
                    "DMARC uses aligned SPF OR aligned DKIM. Current DKIM alignment "
                    f"({dkim_aligned_rate:.2%}) is carrying legitimate authentication."
                ),
                "No action required on the SPF gap at this time.",
                (
                    "Do not add receiver relay/scanner hosts (for example cloud-sec-av.com) "
                    "to SPF unless they are confirmed sender paths."
                ),
                "Optional: continue monitoring for 30 days, then consider BIMI readiness.",
            ]
        )
        if m365_dkim_ready:
            if selector1_cname:
                dynamic_plan.append(f"Observed selector1 CNAME: {selector1_cname}")
            if selector2_cname:
                dynamic_plan.append(f"Observed selector2 CNAME: {selector2_cname}")
    elif m365_spf_gap_expected:
        dynamic_plan.extend(
            [
                (
                    "Microsoft 365 sender paths account for "
                    f"{int(selected_sender.get('dmarc_fail_count_total_m365', selected_sender.get('dmarc_fail_count', 0)))} "
                    "failing messages in this window."
                ),
                "DKIM status: Microsoft 365 DKIM is configured and authenticated.",
                (
                    "SPF alignment lag is commonly caused by Microsoft 365 envelope-from routing and "
                    "does not automatically indicate DMARC enforcement risk."
                ),
                (
                    "DMARC uses aligned SPF OR aligned DKIM. Current aligned DKIM coverage is "
                    f"{dkim_aligned_rate:.2%}."
                ),
                (
                    "Do not add third-party receiver relay/scanner hosts to SPF unless they are "
                    "confirmed sender paths."
                ),
            ]
        )
        if legitimate_fail_rate <= 0.02:
            dynamic_plan.append(
                (
                    "No urgent SPF realignment is required while legitimate DMARC fail rate remains "
                    f"{legitimate_fail_rate:.2%}."
                )
            )
        else:
            dynamic_plan.append(
                (
                    f"Legitimate DMARC fail rate is {legitimate_fail_rate:.2%}; review remaining failing "
                    "flows, then decide whether SPF path changes are needed."
                )
            )
        if m365_dkim_ready:
            dynamic_plan.append(
                (
                    "DNS check confirms selector1/selector2 DKIM CNAME records are present; verify DKIM "
                    "is enabled in the M365 portal if alignment unexpectedly drops."
                )
            )
            if selector1_cname:
                dynamic_plan.append(f"Observed selector1 CNAME: {selector1_cname}")
            if selector2_cname:
                dynamic_plan.append(f"Observed selector2 CNAME: {selector2_cname}")
    elif m365_dkim_ready:
        dynamic_plan.extend(
            [
                (
                    "Microsoft 365 alignment gap detected on outbound protection sender "
                    f"{selected_sender.get('source_ip', 'unknown')} "
                    f"({int(selected_sender.get('dmarc_fail_count_total_m365', selected_sender.get('dmarc_fail_count', 0)))} failing messages across detected M365 sender paths)."
                ),
                (
                    "Preferred fix: enable DKIM for the domain in Microsoft 365 Defender "
                    "(Email & collaboration -> Policies & rules -> Threat policies -> DKIM)."
                ),
                (
                    "DNS check: selector1/selector2 DKIM CNAME records are already present; "
                    "if DKIM alignment is still low, verify DKIM is enabled in the M365 portal."
                ),
                f"Observed selector1 CNAME: {selector1_cname}",
                f"Observed selector2 CNAME: {selector2_cname}",
                "After DNS propagation, enable DKIM in Microsoft 365 and re-run this report in 24-48 hours.",
                "Do not add third-party receiver relay/scanner hosts to SPF unless they are confirmed sender paths.",
            ]
        )
    else:
        dynamic_plan.extend(
            [
                (
                    "Microsoft 365 alignment gap detected on outbound protection sender "
                    f"{selected_sender.get('source_ip', 'unknown')} "
                    f"({int(selected_sender.get('dmarc_fail_count_total_m365', selected_sender.get('dmarc_fail_count', 0)))} failing messages across detected M365 sender paths)."
                ),
                (
                    "Preferred fix: enable DKIM for the domain in Microsoft 365 Defender "
                    "(Email & collaboration -> Policies & rules -> Threat policies -> DKIM)."
                ),
                (
                    "Publish selector1 CNAME: selector1._domainkey -> "
                    f"selector1-{routing_domain}._domainkey.<your-tenant>.onmicrosoft.com"
                ),
                (
                    "Publish selector2 CNAME: selector2._domainkey -> "
                    f"selector2-{routing_domain}._domainkey.<your-tenant>.onmicrosoft.com"
                ),
                "After DNS propagation, enable DKIM in Microsoft 365 and re-run this report in 24-48 hours.",
                "Do not add third-party receiver relay/scanner hosts to SPF unless they are confirmed sender paths.",
            ]
        )

    # Preserve one generic step as a fallback reminder for any non-M365 senders.
    if filtered_default_plan:
        dynamic_plan.append(
            "If non-M365 senders still fail, fix alignment on those specific sender platforms."
        )
    merged = _merge_unique_steps(dynamic_plan, filtered_default_plan)
    return _append_legitimate_dkim_triage_steps(
        merged,
        legitimate_dkim_failure_modes,
        legitimate_forwarding_related_count,
    )


def _filter_m365_spf_low_value_steps(steps: list[str]) -> list[str]:
    blocked_patterns = (
        "custom mail from",
        "return-path",
        "publish spf records on those envelope domains",
        "flatten",
    )
    filtered: list[str] = []
    for step in steps:
        normalized = str(step).strip()
        if not normalized:
            continue
        lower = normalized.lower()
        if any(pattern in lower for pattern in blocked_patterns):
            continue
        filtered.append(normalized)
    return filtered


def _merge_unique_steps(primary: list[str], fallback: list[str]) -> list[str]:
    merged: list[str] = []
    for step in list(primary) + list(fallback):
        normalized = str(step).strip()
        if not normalized:
            continue
        if normalized in merged:
            continue
        merged.append(normalized)
    return merged


def _append_legitimate_dkim_triage_steps(
    steps: list[str],
    legitimate_dkim_failure_modes: dict[str, int],
    legitimate_forwarding_related_count: int,
) -> list[str]:
    triage_steps: list[str] = []
    missing = int(legitimate_dkim_failure_modes.get("dkim_missing", 0))
    auth_fail = int(legitimate_dkim_failure_modes.get("dkim_auth_fail", 0))
    unaligned = int(legitimate_dkim_failure_modes.get("dkim_pass_unaligned", 0))
    if missing > 0:
        triage_steps.append(
            f"DKIM triage: {missing} legitimate failing messages had no DKIM signature. Ensure that sender workflow signs with DKIM."
        )
    if auth_fail > 0:
        triage_steps.append(
            f"DKIM triage: {auth_fail} legitimate failing messages had DKIM authentication failures; investigate relays or content rewrites breaking signatures."
        )
    if unaligned > 0:
        triage_steps.append(
            f"DKIM triage: {unaligned} legitimate failing messages had DKIM pass but unaligned d= domains; configure aligned signing domains/selectors."
        )
    if legitimate_forwarding_related_count > 0:
        triage_steps.append(
            f"Indirect-flow signal: {legitimate_forwarding_related_count} legitimate messages show forwarding/mailing-list/local-policy overrides. Treat SPF failures cautiously and validate DKIM before concluding misconfiguration."
        )
    return _merge_unique_steps(steps, triage_steps)


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


def _reverse_dns(source_ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(source_ip)
        return host
    except Exception:
        return None
