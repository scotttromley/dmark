from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dmark.parser import ParseError, parse_report_bytes
from dmark.reporting import (
    _get_tuned_workers,
    _save_tuned_workers,
    analyze_inputs,
    analyze_uploaded_files,
)


def _sample_xml(report_id: str) -> bytes:
    return f"""\
<feedback>
  <report_metadata>
    <org_name>Receiver Inc</org_name>
    <report_id>{report_id}</report_id>
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
</feedback>
""".encode("utf-8")


class ReportingIntegrationTests(unittest.TestCase):
    def test_analyze_inputs_emits_parse_dedupe_analyze_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "one.xml").write_bytes(_sample_xml("rid-1"))
            (root / "two.xml.gz").write_bytes(gzip.compress(_sample_xml("rid-2")))
            events: list[dict[str, object]] = []
            output = analyze_inputs(
                inputs=[root],
                parse_workers=1,
                progress_callback=events.append,
            )
        phases = [str(item.get("phase", "")) for item in events]
        self.assertIn("parse", phases)
        self.assertIn("dedupe", phases)
        self.assertIn("analyze", phases)
        self.assertEqual(output.get("files_scanned"), 2)
        self.assertEqual(output.get("files_parsed"), 2)

    def test_analyze_uploaded_files_parallel_parsing_reports_worker_count(self) -> None:
        events: list[dict[str, object]] = []
        output = analyze_uploaded_files(
            files=[
                ("one.xml", _sample_xml("rid-1")),
                ("two.xml", _sample_xml("rid-2")),
            ],
            parse_workers=2,
            progress_callback=events.append,
        )
        self.assertEqual(output.get("files_parsed"), 2)
        parse_events = [item for item in events if str(item.get("phase", "")) == "parse"]
        self.assertGreater(len(parse_events), 0)
        self.assertTrue(any(int(item.get("workers", 0)) == 2 for item in parse_events))

    def test_analyze_inputs_raises_when_no_candidates_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ParseError):
                analyze_inputs(inputs=[Path(tmpdir)])

    def test_analyze_uploaded_files_stop_on_error_raises_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            analyze_uploaded_files(
                files=[
                    ("valid.xml", _sample_xml("rid-1")),
                    ("broken.xml", b"<feedback><broken"),
                ],
                stop_on_error=True,
                parse_workers=1,
            )

    def test_parse_worker_tuning_cache_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "parse_tuning.json"
            with patch("dmark.reporting._autotune_cache_path", return_value=cache_path):
                _save_tuned_workers(7)
                self.assertEqual(_get_tuned_workers(), 7)
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
                payload["key"] = "other-key"
                cache_path.write_text(json.dumps(payload), encoding="utf-8")
                self.assertIsNone(_get_tuned_workers())

    def test_analyze_inputs_autotunes_workers_for_large_candidate_sets(self) -> None:
        fake_candidates = [Path(f"fake-{index}.xml") for index in range(205)]
        sample_report = parse_report_bytes(_sample_xml("rid-1"), source_name="sample.xml")
        events: list[dict[str, object]] = []

        with (
            patch("dmark.reporting.collect_candidates", return_value=fake_candidates),
            patch("dmark.reporting._get_tuned_workers", return_value=None),
            patch("dmark.reporting._autotune_parse_workers", return_value=3) as autotune_mock,
            patch("dmark.reporting._save_tuned_workers") as save_mock,
            patch("dmark.reporting.parse_report_file", return_value=sample_report),
            patch("dmark.reporting._load_sender_history", return_value={}),
            patch("dmark.reporting._load_approved_sender_map", return_value={}),
            patch("dmark.reporting._save_sender_history"),
        ):
            output = analyze_inputs(
                inputs=[Path("ignored")],
                parse_workers=0,
                progress_callback=events.append,
            )

        autotune_mock.assert_called_once()
        save_mock.assert_called_once_with(3)
        self.assertEqual(output.get("files_scanned"), 205)
        self.assertEqual(output.get("files_parsed"), 205)
        self.assertEqual(output.get("duplicate_reports_skipped"), 204)
        parse_events = [event for event in events if str(event.get("phase", "")) == "parse"]
        self.assertTrue(any(int(event.get("workers", 0)) == 3 for event in parse_events))

    def test_analyze_inputs_uses_cached_worker_tuning_before_autotune(self) -> None:
        fake_candidates = [Path(f"fake-{index}.xml") for index in range(205)]
        sample_report = parse_report_bytes(_sample_xml("rid-1"), source_name="sample.xml")
        events: list[dict[str, object]] = []

        with (
            patch("dmark.reporting.collect_candidates", return_value=fake_candidates),
            patch("dmark.reporting._get_tuned_workers", return_value=6),
            patch("dmark.reporting._autotune_parse_workers") as autotune_mock,
            patch("dmark.reporting._save_tuned_workers") as save_mock,
            patch("dmark.reporting.parse_report_file", return_value=sample_report),
            patch("dmark.reporting._load_sender_history", return_value={}),
            patch("dmark.reporting._load_approved_sender_map", return_value={}),
            patch("dmark.reporting._save_sender_history"),
        ):
            output = analyze_inputs(
                inputs=[Path("ignored")],
                parse_workers=0,
                progress_callback=events.append,
            )

        autotune_mock.assert_not_called()
        save_mock.assert_not_called()
        self.assertEqual(output.get("files_parsed"), 205)
        parse_events = [event for event in events if str(event.get("phase", "")) == "parse"]
        self.assertTrue(any(int(event.get("workers", 0)) == 6 for event in parse_events))


if __name__ == "__main__":
    unittest.main()
