from __future__ import annotations

from dataclasses import dataclass, field

# Re-export extracted functions so that existing callers (including tests) that
# import from ``dmark.models`` continue to work without changes.
from .action_plan import (  # noqa: F401
    _append_legitimate_dkim_triage_steps,
    _build_dynamic_action_plan,
    _filter_m365_spf_low_value_steps,
    _merge_unique_steps,
)
from .classification import (  # noqa: F401
    _M365_ACTION_MIN_FAIL_MESSAGES,
    _M365_HEAVY_MESSAGE_SHARE_THRESHOLD,
    _classify_source,
    _dynamic_auto_approve_min_volume,
    _is_m365_dkim_carrying_load,
    _is_microsoft365_outbound_ip,
    _select_m365_alignment_sender,
)
from .dns import (  # noqa: F401
    _lookup_cname_record,
    _lookup_cname_record_nslookup,
    _lookup_txt_records,
    _lookup_txt_records_nslookup,
    _resolve_domain_dns_diagnostics,
    _reverse_dns,
    _run_nslookup,
)
from .scoring import (  # noqa: F401
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
from .time_series import (  # noqa: F401
    _build_daily_time_series,
    _legitimate_day_basis_counts,
    _legitimate_dkim_failure_modes,
    _source_dkim_failure_mode,
    _sum_day_counts_for_sources,
    _top_items,
    _top_items_for_source,
)


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
        # Keep DomainSummary as a compact data model; payload construction lives
        # in a dedicated module to keep this class maintainable.
        from .summary_payload import build_domain_summary_payload

        return build_domain_summary_payload(
            summary=self,
            resolve_source_ips=resolve_source_ips,
            resolve_dns_records=resolve_dns_records,
            previous_sender_history=previous_sender_history,
            approved_senders=approved_senders,
        )
