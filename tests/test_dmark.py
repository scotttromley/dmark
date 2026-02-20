from __future__ import annotations

import gzip
import unittest
from unittest.mock import patch

from dmark.analyzer import analyze_reports, report_set_to_unique_reports
from dmark.models import (
    DomainSummary,
    _classify_source,
    _lookup_txt_records_nslookup,
    _reframe_issues_for_attack_pressure,
    _select_m365_alignment_sender,
)
from dmark.parser import parse_report_bytes, parse_report_xml
from dmark.reporting import analyze_uploaded_files


SAMPLE_XML = b"""\
<feedback>
  <report_metadata>
    <org_name>Receiver Inc</org_name>
    <report_id>abc-123</report_id>
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


class DmarkTests(unittest.TestCase):
    def test_parse_from_xml(self) -> None:
        report = parse_report_xml(SAMPLE_XML, source_name="sample.xml")
        self.assertEqual(report.org_name, "Receiver Inc")
        self.assertEqual(report.policy_domain, "example.com")
        self.assertEqual(len(report.records), 2)
        self.assertEqual(report.records[0].envelope_from, "mailer.example.com")
        self.assertEqual(report.records[0].dkim_results[0].selector, "s1")

    def test_parse_from_gzip_file(self) -> None:
        report = parse_report_bytes(gzip.compress(SAMPLE_XML), source_name="report.xml.gz")
        self.assertEqual(report.report_id, "abc-123")

    def test_analysis_counts(self) -> None:
        report = parse_report_xml(SAMPLE_XML, source_name="sample.xml")
        summary_by_domain = analyze_reports([report])
        summary = summary_by_domain["example.com"]
        self.assertEqual(summary.messages_total, 15)
        self.assertEqual(summary.dmarc_pass_count, 10)
        self.assertEqual(summary.dmarc_fail_count, 5)
        self.assertEqual(summary.override_reason_counts.get("forwarded", 0), 10)
        self.assertEqual(summary.dkim_auth_pass_count, 10)
        self.assertEqual(summary.spf_auth_pass_count, 0)
        self.assertEqual(summary.source_pass_counts.get("203.0.113.1", 0), 10)
        self.assertEqual(summary.source_fail_counts.get("198.51.100.9", 0), 5)

    def test_dedupe(self) -> None:
        report_a = parse_report_xml(SAMPLE_XML, source_name="a.xml")
        report_b = parse_report_xml(SAMPLE_XML, source_name="b.xml")
        unique, skipped = report_set_to_unique_reports([report_a, report_b])
        self.assertEqual(len(unique), 1)
        self.assertEqual(skipped, 1)

    def test_upload_analysis(self) -> None:
        output = analyze_uploaded_files(
            files=[
                ("one.xml", SAMPLE_XML),
                ("two.xml.gz", gzip.compress(SAMPLE_XML)),
            ]
        )
        self.assertEqual(output["files_scanned"], 2)
        self.assertEqual(output["files_parsed"], 2)
        self.assertEqual(output["duplicate_reports_skipped"], 1)
        self.assertIn("approved_sender_config_detected", output)
        self.assertIn("health_score", output["domains"][0])
        self.assertIn("deliverability_safety_score", output["domains"][0])
        self.assertIn("anti_spoofing_posture_score", output["domains"][0])
        self.assertIn("dominant_policy", output["domains"][0])
        self.assertIn("enforcement_readiness", output["domains"][0])
        self.assertIn("readiness_gate", output["domains"][0])
        self.assertIn("legitimate_basis", output["domains"][0])
        self.assertIn("historical_trend_score", output["domains"][0])
        self.assertIn("historical_trend_score_title", output["domains"][0])
        self.assertIn("aggregate_evidence_note", output["domains"][0])
        self.assertIn("protection_posture_grade", output["domains"][0])
        self.assertIn("authentication_coverage_rate", output["domains"][0])
        self.assertIn("attack_pressure_level", output["domains"][0])
        self.assertIn("time_series", output["domains"][0])
        self.assertIn("time_series_days", output["domains"][0])
        self.assertIn("time_series_start", output["domains"][0])
        self.assertIn("time_series_end", output["domains"][0])
        self.assertIn("health_score_summary", output["domains"][0])
        self.assertIn("health_score_breakdown", output["domains"][0])
        self.assertIn("health_score_causes", output["domains"][0])
        self.assertIn("dkim_auth_pass_rate", output["domains"][0])
        self.assertIn("spf_auth_pass_rate", output["domains"][0])
        self.assertIn("dkim_alignment_gap_rate", output["domains"][0])
        self.assertIn("spf_alignment_gap_rate", output["domains"][0])
        self.assertIn("policy_impact_simulation", output["domains"][0])
        self.assertIn("evidence_overview", output["domains"][0])
        self.assertIn("sender_inventory", output["domains"][0])
        self.assertIn("issues", output["domains"][0])
        self.assertIn("action_plan", output["domains"][0])
        self.assertIn("hostname", output["domains"][0]["top_failing_sources"][0])
        self.assertIn("classification", output["domains"][0]["top_failing_sources"][0])
        self.assertIn("evidence_details", output["domains"][0]["top_failing_sources"][0])
        self.assertIn("classification", output["domains"][0]["sender_inventory"][0])
        self.assertIn("legit_status", output["domains"][0]["sender_inventory"][0])
        self.assertIn("message_share_rate", output["domains"][0]["sender_inventory"][0])
        self.assertIn("noise_messages_excluded_from_safety", output["domains"][0])
        self.assertIn("deliverability_safety_note", output["domains"][0])
        self.assertIn("sender_inventory_summary", output["domains"][0])
        self.assertIn("dns_diagnostics", output["domains"][0])
        self.assertIn(
            "receiver_side_security_relay_note",
            output["domains"][0],
        )
        self.assertGreater(len(output["domains"][0]["time_series"]), 0)
        self.assertGreater(len(output["domains"][0]["issues"]), 0)
        self.assertGreater(len(output["domains"][0]["action_plan"]), 0)
        first_issue = output["domains"][0]["issues"][0]
        self.assertIn("category", first_issue)
        self.assertIn("confidence", first_issue)
        self.assertIn("evidence_details", first_issue)

    def test_upload_analysis_progress_callback(self) -> None:
        events: list[dict[str, object]] = []

        analyze_uploaded_files(
            files=[
                ("one.xml", SAMPLE_XML),
                ("two.xml.gz", gzip.compress(SAMPLE_XML)),
            ],
            progress_callback=events.append,
        )

        phases = [str(event.get("phase", "")) for event in events]
        self.assertIn("parse", phases)
        self.assertIn("dedupe", phases)
        self.assertIn("analyze", phases)

    def test_microsoft_ip_signature_classification_without_hostname(self) -> None:
        classification = _classify_source("2a01:111:f403:c103::3", None)
        self.assertEqual(classification["category"], "esp_microsoft365_outbound")
        self.assertEqual(classification["action"], "fix_alignment")

    def test_dynamic_auto_approval_threshold_for_small_domain(self) -> None:
        summary = DomainSummary(domain="small.example")
        summary.messages_total = 1806
        summary.dmarc_pass_count = 1806
        summary.policy_counts["reject"] = 1
        summary.policy_pct_total = 100
        summary.policy_pct_reports = 1
        summary.source_message_counts["198.51.100.9"] = 96
        summary.source_pass_counts["198.51.100.9"] = 96
        summary.source_message_counts["203.0.113.10"] = 1710
        summary.source_pass_counts["203.0.113.10"] = 1710

        payload = summary.to_dict(resolve_source_ips=False)
        sender_map = {
            str(item.get("source_ip")): item
            for item in payload.get("sender_inventory", [])
            if isinstance(item, dict)
        }
        self.assertEqual(
            sender_map["198.51.100.9"]["classification"],
            "observed_high_pass_sender",
        )
        self.assertEqual(sender_map["198.51.100.9"]["legit_status"], "approved")

    def test_auto_approval_does_not_overwrite_m365_classification(self) -> None:
        summary = DomainSummary(domain="m365.example")
        summary.messages_total = 120
        summary.dmarc_pass_count = 120
        summary.policy_counts["reject"] = 1
        summary.policy_pct_total = 100
        summary.policy_pct_reports = 1
        summary.source_message_counts["2a01:111:f403:c103::3"] = 120
        summary.source_pass_counts["2a01:111:f403:c103::3"] = 120

        payload = summary.to_dict(resolve_source_ips=False)
        sender_map = {
            str(item.get("source_ip")): item
            for item in payload.get("sender_inventory", [])
            if isinstance(item, dict)
        }
        self.assertEqual(
            sender_map["2a01:111:f403:c103::3"]["classification"],
            "esp_microsoft365_outbound",
        )
        self.assertEqual(
            sender_map["2a01:111:f403:c103::3"]["suggested_action"],
            "fix_alignment",
        )

    def test_dynamic_action_plan_without_reverse_dns_for_m365_ip_signature(self) -> None:
        xml = SAMPLE_XML.replace(b"<p>none</p>", b"<p>reject</p>", 1)
        xml = xml.replace(b"<sp>none</sp>", b"<sp>reject</sp>", 1)
        xml = xml.replace(
            b"<source_ip>198.51.100.9</source_ip>",
            b"<source_ip>2a01:111:f403:c103::3</source_ip>",
            1,
        )
        report = parse_report_xml(xml, source_name="m365-ip-signature.xml")
        summary_by_domain = analyze_reports([report])
        summary = summary_by_domain["example.com"]
        payload = summary.to_dict(resolve_source_ips=False)

        action_plan = payload.get("action_plan", [])
        self.assertGreater(len(action_plan), 0)
        self.assertTrue(any("Microsoft 365" in str(step) for step in action_plan))

    def test_dynamic_action_plan_for_m365_alignment(self) -> None:
        xml = SAMPLE_XML.replace(b"<p>none</p>", b"<p>reject</p>", 1)
        xml = xml.replace(b"<sp>none</sp>", b"<sp>reject</sp>", 1)
        report = parse_report_xml(xml, source_name="m365.xml")
        summary_by_domain = analyze_reports([report])
        summary = summary_by_domain["example.com"]

        def fake_reverse_dns(ip: str) -> str | None:
            if ip == "198.51.100.9":
                return "mail-canadacentralazlp170120003.outbound.protection.outlook.com"
            return None

        with patch("dmark.models._reverse_dns", side_effect=fake_reverse_dns):
            payload = summary.to_dict(resolve_source_ips=True)

        action_plan = payload.get("action_plan", [])
        self.assertGreater(len(action_plan), 0)
        self.assertIn("CRITICAL", str(action_plan[0]))
        self.assertTrue(
            any("selector1._domainkey" in str(step) for step in action_plan)
        )
        self.assertTrue(
            any("Microsoft 365" in str(step) for step in action_plan)
        )

    def test_dns_diagnostics_enabled_output(self) -> None:
        report = parse_report_xml(SAMPLE_XML, source_name="dns.xml")
        summary = analyze_reports([report])["example.com"]
        fake_dns = {
            "enabled": True,
            "domain": "example.com",
            "dmarc_record_found": True,
            "spf_record_found": True,
            "m365_dkim_status": "configured",
            "dkim_selector_checks": {},
        }
        with patch("dmark.models._resolve_domain_dns_diagnostics", return_value=fake_dns):
            payload = summary.to_dict(resolve_dns_records=True)
        dns_data = payload.get("dns_diagnostics", {})
        self.assertTrue(dns_data.get("enabled"))
        self.assertTrue(dns_data.get("dmarc_record_found"))
        self.assertTrue(dns_data.get("spf_record_found"))

    def test_dynamic_action_plan_uses_existing_m365_dkim_cnames(self) -> None:
        xml = SAMPLE_XML.replace(b"<p>none</p>", b"<p>reject</p>", 1)
        xml = xml.replace(b"<sp>none</sp>", b"<sp>reject</sp>", 1)
        xml = xml.replace(
            b"<source_ip>198.51.100.9</source_ip>",
            b"<source_ip>2a01:111:f403:c103::3</source_ip>",
            1,
        )
        report = parse_report_xml(xml, source_name="dns-m365.xml")
        summary = analyze_reports([report])["example.com"]
        fake_dns = {
            "enabled": True,
            "domain": "example.com",
            "dmarc_record_found": True,
            "spf_record_found": True,
            "m365_dkim_status": "configured",
            "dkim_selector_checks": {
                "selector1": {"cname": "selector1-example-com._domainkey.tenant.onmicrosoft.com"},
                "selector2": {"cname": "selector2-example-com._domainkey.tenant.onmicrosoft.com"},
            },
        }
        with patch("dmark.models._resolve_domain_dns_diagnostics", return_value=fake_dns):
            payload = summary.to_dict(resolve_dns_records=True)
        action_plan = payload.get("action_plan", [])
        self.assertTrue(any("already present" in str(step) for step in action_plan))
        self.assertTrue(any("Observed selector1 CNAME" in str(step) for step in action_plan))

    def test_nslookup_txt_parser_handles_windows_multiline_format(self) -> None:
        sample_output = """
Server:  UnKnown
Address:  192.168.0.1

_dmarc.cca.one\ttext =

\t"v=DMARC1; p=reject; rua=mailto:dmarcreports@cca.one"
cca.one\ttext =

\t"v=spf1 include:spf.protection.outlook.com ~all"
Non-authoritative answer:
"""
        with patch("dmark.models._run_nslookup", return_value=sample_output):
            records = _lookup_txt_records_nslookup("cca.one")
        self.assertTrue(any(item.lower().startswith("v=dmarc1") for item in records))
        self.assertTrue(any(item.lower().startswith("v=spf1") for item in records))

    def test_select_m365_alignment_sender_uses_all_classified_sources(self) -> None:
        selected = _select_m365_alignment_sender(
            source_fail_counts={
                "203.0.113.10": 200,
                "2a01:111:f403:d917::": 15,
                "2a01:111:f403:c103::3": 6,
            },
            source_message_counts={
                "203.0.113.10": 5000,
                "2a01:111:f403:d917::": 18,
                "2a01:111:f403:c103::3": 2000,
            },
            classified_sources={
                "203.0.113.10": {"category": "unknown"},
                "2a01:111:f403:d917::": {"category": "esp_microsoft365_outbound"},
                "2a01:111:f403:c103::3": {"category": "esp_microsoft365_outbound"},
            },
        )
        self.assertIsNotNone(selected)
        self.assertEqual(selected["source_ip"], "2a01:111:f403:d917::")

    def test_reframe_issues_for_attack_pressure(self) -> None:
        reframed = _reframe_issues_for_attack_pressure(
            issues=[
                {
                    "id": "high_dmarc_fail_rate",
                    "category": "unauthorized_or_misconfigured_sources",
                    "severity": "high",
                    "confidence": "high",
                    "title": "DMARC fail rate is materially high.",
                    "evidence": "4.00% failed.",
                }
            ],
            dominant_policy="reject",
            legitimate_fail_rate=0.001,
            attack_pressure={
                "unauthorized_fail_count": 500,
                "unauthorized_fail_rate": 0.04,
            },
            messages_total=12000,
        )
        self.assertEqual(len(reframed), 1)
        self.assertEqual(reframed[0]["category"], "attack_pressure")
        self.assertIn("Attack pressure", str(reframed[0]["title"]))

    def test_m365_dkim_carrying_load_removes_low_value_spf_steps(self) -> None:
        summary = DomainSummary(domain="example.com")
        summary.messages_total = 1000
        summary.dmarc_pass_count = 995
        summary.dmarc_fail_count = 5
        summary.dkim_auth_pass_count = 960
        summary.dkim_aligned_pass_count = 930
        summary.spf_auth_pass_count = 950
        summary.spf_aligned_pass_count = 700
        summary.spf_alignment_gap_count = 250
        summary.policy_counts["reject"] = 1
        summary.policy_pct_total = 100
        summary.policy_pct_reports = 1
        summary.source_message_counts["2a01:111:f403:c103::3"] = 900
        summary.source_pass_counts["2a01:111:f403:c103::3"] = 900
        summary.source_message_counts["203.0.113.10"] = 100
        summary.source_pass_counts["203.0.113.10"] = 95
        summary.source_fail_counts["203.0.113.10"] = 5
        summary.failing_source_counts["203.0.113.10"] = 5
        summary.action_plan = [
            "Review top failing sources and identify which are legitimate systems.",
            "For each sender service, configure a custom MAIL FROM/Return-Path domain under your domain.",
            "Publish SPF records on those envelope domains including all legitimate sender infrastructure.",
            "Keep SPF under DNS lookup limits and flatten where needed.",
        ]
        fake_dns = {
            "enabled": True,
            "domain": "example.com",
            "dmarc_record_found": True,
            "spf_record_found": True,
            "m365_dkim_status": "configured",
            "dkim_selector_checks": {
                "selector1": {"cname": "selector1-example-com._domainkey.tenant.onmicrosoft.com"},
                "selector2": {"cname": "selector2-example-com._domainkey.tenant.onmicrosoft.com"},
            },
        }
        with patch("dmark.models._resolve_domain_dns_diagnostics", return_value=fake_dns):
            payload = summary.to_dict(resolve_dns_records=True)

        action_plan = [str(item) for item in payload.get("action_plan", [])]
        joined = " ".join(action_plan).lower()
        self.assertIn("dmarc uses aligned spf or aligned dkim", joined)
        self.assertIn("no action required on the spf gap", joined)
        self.assertNotIn("custom mail from", joined)
        self.assertNotIn("flatten", joined)
        sender_rows = payload.get("sender_inventory", [])
        self.assertTrue(isinstance(sender_rows, list) and len(sender_rows) > 0)
        m365_row = next(
            (
                row
                for row in sender_rows
                if isinstance(row, dict)
                and row.get("classification") == "esp_microsoft365_outbound"
            ),
            None,
        )
        self.assertIsNotNone(m365_row)
        self.assertEqual(
            m365_row.get("legit_status_label"),
            "approved (DKIM carrying load)",
        )
        self.assertEqual(
            m365_row.get("suggested_action_label"),
            "monitor - no action needed",
        )

    def test_m365_expected_spf_gap_branch_suppresses_critical_banner(self) -> None:
        summary = DomainSummary(domain="example.com")
        summary.messages_total = 1000
        summary.dmarc_pass_count = 980
        summary.dmarc_fail_count = 20
        summary.dkim_auth_pass_count = 950
        summary.dkim_aligned_pass_count = 920
        summary.spf_auth_pass_count = 940
        summary.spf_aligned_pass_count = 700
        summary.spf_alignment_gap_count = 240
        summary.policy_counts["reject"] = 1
        summary.policy_pct_total = 100
        summary.policy_pct_reports = 1
        summary.source_message_counts["2a01:111:f403:c103::3"] = 950
        summary.source_pass_counts["2a01:111:f403:c103::3"] = 935
        summary.source_fail_counts["2a01:111:f403:c103::3"] = 15
        summary.failing_source_counts["2a01:111:f403:c103::3"] = 15
        summary.source_message_counts["203.0.113.10"] = 50
        summary.source_pass_counts["203.0.113.10"] = 45
        summary.source_fail_counts["203.0.113.10"] = 5
        summary.failing_source_counts["203.0.113.10"] = 5
        fake_dns = {
            "enabled": True,
            "domain": "example.com",
            "dmarc_record_found": True,
            "spf_record_found": True,
            "m365_dkim_status": "configured",
            "dkim_selector_checks": {
                "selector1": {"cname": "selector1-example-com._domainkey.tenant.onmicrosoft.com"},
                "selector2": {"cname": "selector2-example-com._domainkey.tenant.onmicrosoft.com"},
            },
        }
        with patch("dmark.models._resolve_domain_dns_diagnostics", return_value=fake_dns):
            payload = summary.to_dict(resolve_dns_records=True)

        action_plan = [str(item) for item in payload.get("action_plan", [])]
        self.assertFalse(any(step.startswith("CRITICAL:") for step in action_plan))


if __name__ == "__main__":
    unittest.main()
