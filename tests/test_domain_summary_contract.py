from __future__ import annotations

import unittest

from dmark.analyzer import analyze_reports
from dmark.parser import parse_report_xml


SAMPLE_XML = b"""\
<feedback>
  <report_metadata>
    <org_name>Receiver Inc</org_name>
    <report_id>contract-1</report_id>
    <date_range>
      <begin>1700000000</begin>
      <end>1700086400</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.1</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <reason>
          <type>forwarded</type>
        </reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>mailer.example.com</envelope_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>mailer.example.com</domain>
        <selector>s1</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.9</source_ip>
      <count>5</count>
      <policy_evaluated>
        <disposition>none</disposition>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>bad-domain.net</envelope_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>bad-domain.net</domain>
        <result>fail</result>
      </dkim>
      <spf>
        <domain>bad-domain.net</domain>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
</feedback>
"""

EXPECTED_DOMAIN_KEYS = {
    "action_plan",
    "aggregate_evidence_note",
    "anti_spoofing_posture_breakdown",
    "anti_spoofing_posture_score",
    "approved_sender_count",
    "attack_pressure_fail_count",
    "attack_pressure_fail_rate",
    "attack_pressure_label",
    "attack_pressure_level",
    "attack_pressure_note",
    "auth_breakdown",
    "authentication_coverage_blended_rate",
    "authentication_coverage_dkim_rate",
    "authentication_coverage_rate",
    "authentication_coverage_spf_rate",
    "auto_approved_sender_count",
    "average_policy_pct",
    "deliverability_safety_breakdown",
    "deliverability_safety_note",
    "deliverability_safety_score",
    "disposition_counts",
    "dkim_aligned_pass_rate",
    "dkim_alignment_gap_rate",
    "dkim_auth_pass_rate",
    "dmarc_fail_count",
    "dmarc_fail_rate",
    "dmarc_pass_count",
    "dmarc_pass_rate",
    "dns_diagnostics",
    "domain",
    "dominant_policy",
    "enforcement_observed_rate",
    "enforcement_readiness",
    "enforcement_readiness_detail",
    "evidence_overview",
    "health_label",
    "health_score",
    "health_score_breakdown",
    "health_score_causes",
    "health_score_summary",
    "historical_trend_label",
    "historical_trend_score",
    "historical_trend_score_description",
    "historical_trend_score_title",
    "is_m365_heavy",
    "issues",
    "legitimate_basis",
    "m365_dkim_carrying_load",
    "m365_failing_messages",
    "m365_message_count",
    "m365_message_rate",
    "messages_total",
    "new_sender_count",
    "noise_failures_excluded_from_safety",
    "noise_messages_excluded_from_safety",
    "policy_consistency",
    "policy_impact_simulation",
    "protection_posture_detail",
    "protection_posture_grade",
    "protection_posture_score",
    "published_policy_counts",
    "readiness_gate",
    "receiver_side_security_relay_fail_count",
    "receiver_side_security_relay_fail_share",
    "receiver_side_security_relay_note",
    "receiver_side_security_relay_sources",
    "recommendations",
    "reports_seen",
    "score_confidence",
    "sender_inventory",
    "sender_inventory_summary",
    "spf_aligned_pass_rate",
    "spf_alignment_gap_rate",
    "spf_auth_pass_rate",
    "time_series",
    "time_series_days",
    "time_series_end",
    "time_series_start",
    "top_failing_source_share",
    "top_failing_sources",
}

EXPECTED_SENDER_KEYS = {
    "approved_sender",
    "classification",
    "classification_confidence",
    "classification_reason",
    "dmarc_fail_count",
    "dmarc_fail_rate",
    "dmarc_pass_count",
    "dmarc_pass_rate",
    "hostname",
    "legit_status",
    "legit_status_label",
    "message_count",
    "message_share_rate",
    "new_since_last_run",
    "source_ip",
    "suggested_action",
    "suggested_action_label",
}

EXPECTED_FAILING_SOURCE_KEYS = {
    "action",
    "category",
    "classification",
    "classification_confidence",
    "classification_reason",
    "dkim_failure_mode",
    "evidence_details",
    "fail_share_rate",
    "hostname",
    "investigation_confidence",
    "investigation_note",
    "legit_status",
    "message_count",
    "source_ip",
}

EXPECTED_EVIDENCE_DETAILS_KEYS = {
    "aggregate_record_notice",
    "top_dispositions",
    "top_dkim_domains",
    "top_dkim_results",
    "top_dkim_selectors",
    "top_envelope_from",
    "top_header_from",
    "top_override_reasons",
    "top_spf_domains",
    "top_spf_results",
}

EXPECTED_TIME_SERIES_KEYS = {
    "approved_messages",
    "attack_pressure_fail_count",
    "attack_pressure_fail_rate",
    "date",
    "dkim_aligned_pass_rate",
    "dmarc_fail_count",
    "dmarc_fail_rate",
    "dmarc_pass_count",
    "legitimate_basis_messages",
    "legitimate_fail_count",
    "legitimate_fail_rate",
    "messages_total",
    "noise_messages",
    "pending_review_messages",
    "spf_aligned_pass_rate",
}

EXPECTED_ISSUE_KEYS = {
    "actions",
    "category",
    "confidence",
    "evidence",
    "evidence_details",
    "id",
    "likely_cause",
    "severity",
    "title",
}


class DomainSummaryContractTests(unittest.TestCase):
    def _build_payload(self) -> dict[str, object]:
        report = parse_report_xml(SAMPLE_XML, source_name="contract.xml")
        summary = analyze_reports([report])["example.com"]
        return summary.to_dict(resolve_source_ips=False, resolve_dns_records=False)

    def test_domain_summary_top_level_keys_contract(self) -> None:
        payload = self._build_payload()
        self.assertEqual(set(payload.keys()), EXPECTED_DOMAIN_KEYS)

    def test_sender_inventory_entry_keys_contract(self) -> None:
        payload = self._build_payload()
        sender_inventory = payload.get("sender_inventory")
        self.assertTrue(isinstance(sender_inventory, list) and sender_inventory)
        first_sender = sender_inventory[0]
        self.assertTrue(isinstance(first_sender, dict))
        self.assertEqual(set(first_sender.keys()), EXPECTED_SENDER_KEYS)

    def test_top_failing_source_keys_contract(self) -> None:
        payload = self._build_payload()
        top_failing_sources = payload.get("top_failing_sources")
        self.assertTrue(isinstance(top_failing_sources, list) and top_failing_sources)
        first_source = top_failing_sources[0]
        self.assertTrue(isinstance(first_source, dict))
        self.assertEqual(set(first_source.keys()), EXPECTED_FAILING_SOURCE_KEYS)
        evidence_details = first_source.get("evidence_details")
        self.assertTrue(isinstance(evidence_details, dict))
        self.assertEqual(set(evidence_details.keys()), EXPECTED_EVIDENCE_DETAILS_KEYS)

    def test_time_series_and_issue_keys_contract(self) -> None:
        payload = self._build_payload()
        time_series = payload.get("time_series")
        self.assertTrue(isinstance(time_series, list) and time_series)
        first_time_series_point = time_series[0]
        self.assertTrue(isinstance(first_time_series_point, dict))
        self.assertEqual(set(first_time_series_point.keys()), EXPECTED_TIME_SERIES_KEYS)

        issues = payload.get("issues")
        self.assertTrue(isinstance(issues, list) and issues)
        first_issue = issues[0]
        self.assertTrue(isinstance(first_issue, dict))
        self.assertEqual(set(first_issue.keys()), EXPECTED_ISSUE_KEYS)


if __name__ == "__main__":
    unittest.main()
