from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from dmark.analyzer import analyze_reports
from dmark.parser import parse_report_xml


_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "domain_summary"
_UPDATE_GOLDENS = os.getenv("DMARK_UPDATE_GOLDENS") == "1"


def _build_report_xml(
    *,
    report_id: str,
    begin: int,
    end: int,
    pass_count: int,
    fail_count: int,
) -> bytes:
    return f"""\
<feedback>
  <report_metadata>
    <org_name>Receiver Inc</org_name>
    <report_id>{report_id}</report_id>
    <date_range>
      <begin>{begin}</begin>
      <end>{end}</end>
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
      <count>{pass_count}</count>
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
      <count>{fail_count}</count>
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
""".encode("utf-8")


class DomainSummaryGoldenTests(unittest.TestCase):
    maxDiff = None

    def _assert_matches_golden(self, fixture_name: str, payload: dict[str, object]) -> None:
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        fixture_path = _FIXTURE_DIR / f"{fixture_name}.json"
        if _UPDATE_GOLDENS:
            fixture_path.parent.mkdir(parents=True, exist_ok=True)
            fixture_path.write_text(serialized, encoding="utf-8")
        if not fixture_path.exists():
            self.fail(
                f"Missing golden fixture {fixture_path}. "
                "Set DMARK_UPDATE_GOLDENS=1 to create it."
            )
        expected = fixture_path.read_text(encoding="utf-8")
        self.assertEqual(
            serialized,
            expected,
            f"Golden mismatch for {fixture_name}. Set DMARK_UPDATE_GOLDENS=1 to refresh.",
        )

    def test_to_dict_snapshot_single_report_baseline(self) -> None:
        report = parse_report_xml(
            _build_report_xml(
                report_id="baseline-1",
                begin=1700000000,
                end=1700086400,
                pass_count=10,
                fail_count=5,
            ),
            source_name="baseline-1.xml",
        )
        summary = analyze_reports([report])["example.com"]
        payload = summary.to_dict(resolve_source_ips=False, resolve_dns_records=False)
        self._assert_matches_golden("single_report_baseline", payload)

    def test_to_dict_snapshot_two_reports_with_sender_context(self) -> None:
        report_one = parse_report_xml(
            _build_report_xml(
                report_id="baseline-1",
                begin=1700000000,
                end=1700086400,
                pass_count=10,
                fail_count=5,
            ),
            source_name="baseline-1.xml",
        )
        report_two = parse_report_xml(
            _build_report_xml(
                report_id="baseline-2",
                begin=1700086400,
                end=1700172800,
                pass_count=15,
                fail_count=4,
            ),
            source_name="baseline-2.xml",
        )
        summary = analyze_reports([report_one, report_two])["example.com"]
        payload = summary.to_dict(
            resolve_source_ips=False,
            resolve_dns_records=False,
            previous_sender_history={"198.51.100.9"},
            approved_senders={"203.0.113.1"},
        )
        self._assert_matches_golden("two_report_with_sender_context", payload)


if __name__ == "__main__":
    unittest.main()
