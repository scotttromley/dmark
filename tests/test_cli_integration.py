from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from dmark.cli import main


SAMPLE_XML = b"""\
<feedback>
  <report_metadata>
    <org_name>Receiver Inc</org_name>
    <report_id>cli-1</report_id>
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
"""


class CliIntegrationTests(unittest.TestCase):
    def test_cli_analyze_writes_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            input_path = root / "sample.xml"
            json_out = root / "out" / "report.json"
            input_path.write_bytes(SAMPLE_XML)

            stdout_buffer = io.StringIO()
            stderr_buffer = io.StringIO()
            with (
                patch.object(
                    sys,
                    "argv",
                    [
                        "dmark",
                        "analyze",
                        str(input_path),
                        "--json-out",
                        str(json_out),
                        "--parse-workers",
                        "1",
                    ],
                ),
                redirect_stdout(stdout_buffer),
                redirect_stderr(stderr_buffer),
            ):
                exit_code = main()

            self.assertEqual(exit_code, 0)
            self.assertTrue(json_out.exists())
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload.get("files_scanned"), 1)
            self.assertEqual(payload.get("files_parsed"), 1)
            domains = payload.get("domains", [])
            self.assertTrue(isinstance(domains, list) and len(domains) == 1)
            self.assertEqual(domains[0].get("domain"), "example.com")
            self.assertEqual(stderr_buffer.getvalue(), "")

    def test_cli_analyze_returns_error_for_empty_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            stdout_buffer = io.StringIO()
            stderr_buffer = io.StringIO()
            with (
                patch.object(sys, "argv", ["dmark", "analyze", tmpdir]),
                redirect_stdout(stdout_buffer),
                redirect_stderr(stderr_buffer),
            ):
                exit_code = main()

        self.assertEqual(exit_code, 2)
        self.assertIn("No candidate report files found", stderr_buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
