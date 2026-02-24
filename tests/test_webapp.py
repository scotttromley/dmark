from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dmark.parser import ParseError
from dmark.webapp import create_app

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


class WebAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.client = self.app.test_client()

    def test_max_upload_mb_is_clamped_to_one(self) -> None:
        app = create_app(max_upload_mb=0)
        self.assertEqual(app.config["MAX_CONTENT_LENGTH"], 1 * 1024 * 1024)

        response = app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Upload size limit: <strong>1 MB</strong>", response.data)

    def test_index_loads(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analyze PST Upload", response.data)

    def test_analyze_upload_endpoint_success(self) -> None:
        response = self.client.post(
            "/api/analyze-upload",
            data={"files": (io.BytesIO(SAMPLE_XML), "sample.xml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload.get("files_scanned"), 1)
        self.assertEqual(payload.get("files_parsed"), 1)
        self.assertEqual(len(payload.get("domains", [])), 1)

    def test_analyze_path_endpoint_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_path = Path(tmpdir) / "sample.xml"
            sample_path.write_bytes(SAMPLE_XML)
            response = self.client.post(
                "/api/analyze-path",
                json={"path": str(sample_path)},
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload.get("files_scanned"), 1)
        self.assertEqual(payload.get("files_parsed"), 1)
        self.assertEqual(len(payload.get("domains", [])), 1)

    def test_analyze_path_rejects_missing_path(self) -> None:
        response = self.client.post(
            "/api/analyze-path",
            json={"path": r"Z:\definitely\missing\path"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Path not found", response.data)

    def test_analyze_path_rejects_empty_payload(self) -> None:
        response = self.client.post("/api/analyze-path", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Missing required field: path", response.data)

    def test_analyze_path_parse_error_returns_400(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_path = Path(tmpdir) / "sample.xml"
            sample_path.write_bytes(SAMPLE_XML)
            with patch("dmark.webapp.analyze_inputs", side_effect=ParseError("bad report")):
                response = self.client.post(
                    "/api/analyze-path",
                    json={"path": str(sample_path)},
                )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"bad report", response.data)

    def test_analyze_path_uses_supplied_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_path = Path(tmpdir) / "sample.xml"
            sample_path.write_bytes(SAMPLE_XML)
            with patch(
                "dmark.webapp.analyze_inputs",
                return_value={
                    "files_scanned": 1,
                    "files_parsed": 1,
                    "parse_errors": 0,
                    "duplicate_reports_skipped": 0,
                    "domains": [],
                    "approved_sender_config_detected": False,
                },
            ) as mocked:
                response = self.client.post(
                    "/api/analyze-path",
                    json={
                        "path": str(sample_path),
                        "min_fail_rate_alert": 0.15,
                        "min_messages_alert": 250,
                    },
                )

        self.assertEqual(response.status_code, 200)
        call = mocked.call_args
        self.assertIsNotNone(call)
        kwargs = call.kwargs
        self.assertEqual(kwargs["min_fail_rate_alert"], 0.15)
        self.assertEqual(kwargs["min_messages_alert"], 250)
        self.assertEqual(kwargs["parse_workers"], 0)

    def test_analyze_path_invalid_thresholds_fall_back_to_defaults(self) -> None:
        app = create_app(min_fail_rate_alert=0.11, min_messages_alert=123)
        client = app.test_client()
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_path = Path(tmpdir) / "sample.xml"
            sample_path.write_bytes(SAMPLE_XML)
            with patch(
                "dmark.webapp.analyze_inputs",
                return_value={
                    "files_scanned": 1,
                    "files_parsed": 1,
                    "parse_errors": 0,
                    "duplicate_reports_skipped": 0,
                    "domains": [],
                    "approved_sender_config_detected": False,
                },
            ) as mocked:
                response = client.post(
                    "/api/analyze-path",
                    json={
                        "path": str(sample_path),
                        "min_fail_rate_alert": -1,
                        "min_messages_alert": 0,
                    },
                )

        self.assertEqual(response.status_code, 200)
        kwargs = mocked.call_args.kwargs
        self.assertEqual(kwargs["min_fail_rate_alert"], 0.11)
        self.assertEqual(kwargs["min_messages_alert"], 123)

    def test_analyze_upload_rejects_candidate_less_payload(self) -> None:
        response = self.client.post(
            "/api/analyze-upload",
            data={"files": (io.BytesIO(b"not xml"), "notes.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"No candidate report files found in upload.", response.data)

    def test_analyze_upload_mixed_valid_and_malformed_xml(self) -> None:
        response = self.client.post(
            "/api/analyze-upload",
            data={
                "files": [
                    (io.BytesIO(SAMPLE_XML), "valid.xml"),
                    (io.BytesIO(b"<feedback><broken"), "broken.xml"),
                ]
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload.get("files_scanned"), 2)
        self.assertEqual(payload.get("files_parsed"), 1)
        self.assertEqual(payload.get("parse_errors"), 1)

    def test_analyze_upload_uses_supplied_thresholds(self) -> None:
        with patch(
            "dmark.webapp.analyze_uploaded_files",
            return_value={
                "files_scanned": 1,
                "files_parsed": 1,
                "parse_errors": 0,
                "duplicate_reports_skipped": 0,
                "domains": [],
                "approved_sender_config_detected": False,
            },
        ) as mocked:
            response = self.client.post(
                "/api/analyze-upload",
                data={
                    "min_fail_rate_alert": "0.07",
                    "min_messages_alert": "777",
                    "files": (io.BytesIO(SAMPLE_XML), "sample.xml"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 200)
        kwargs = mocked.call_args.kwargs
        self.assertEqual(kwargs["min_fail_rate_alert"], 0.07)
        self.assertEqual(kwargs["min_messages_alert"], 777)
        self.assertEqual(kwargs["parse_workers"], 0)

    def test_pst_upload_requires_file(self) -> None:
        response = self.client.post("/api/analyze-pst-upload", data={})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"No PST file was provided", response.data)

    def test_pst_upload_returns_job(self) -> None:
        response = self.client.post(
            "/api/analyze-pst-upload",
            data={"pst_file": (io.BytesIO(b"fake pst payload"), "sample.pst")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 202)
        payload = response.get_json()
        self.assertIn("job_id", payload)

        status_response = self.client.get(f"/api/pst-job/{payload['job_id']}")
        self.assertEqual(status_response.status_code, 200)
        self.assertIn(b"status", status_response.data)

    def test_pst_job_not_found(self) -> None:
        response = self.client.get("/api/pst-job/not-a-real-job")
        self.assertEqual(response.status_code, 404)

    def test_pst_job_retention_prunes_old_terminal_jobs(self) -> None:
        class _InlineThread:
            def __init__(self, target=None, daemon=None):
                self._target = target
                self.daemon = daemon

            def start(self) -> None:
                if self._target is not None:
                    self._target()

        def _fake_result(*_args, **_kwargs) -> dict[str, object]:
            return {
                "files_scanned": 1,
                "files_parsed": 1,
                "parse_errors": 0,
                "duplicate_reports_skipped": 0,
                "domains": [],
                "approved_sender_config_detected": False,
            }

        with (
            patch(
                "dmark.webapp.extract_reports_from_pst",
                return_value=([Path("sample.xml")], "auto"),
            ),
            patch("dmark.webapp.analyze_inputs", side_effect=_fake_result),
            patch(
                "dmark.webapp.threading.Thread",
                side_effect=lambda target, daemon: _InlineThread(target=target, daemon=daemon),
            ),
        ):
            app = create_app(max_jobs=1, job_ttl_seconds=3600)
            client = app.test_client()
            job_ids: list[str] = []
            for _ in range(2):
                response = client.post(
                    "/api/analyze-pst-upload",
                    data={"pst_file": (io.BytesIO(b"fake pst payload"), "sample.pst")},
                    content_type="multipart/form-data",
                )
                self.assertEqual(response.status_code, 202)
                payload = response.get_json()
                job_ids.append(str(payload["job_id"]))

            first_response = client.get(f"/api/pst-job/{job_ids[0]}")
            second_response = client.get(f"/api/pst-job/{job_ids[1]}")
            self.assertEqual(first_response.status_code, 404)
            self.assertEqual(second_response.status_code, 200)
            second_payload = second_response.get_json()
            self.assertEqual(second_payload.get("status"), "complete")

    def test_capabilities_endpoint(self) -> None:
        response = self.client.get("/api/capabilities")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"pst_extractors", response.data)
        self.assertIn(b"pstparse_dotnet", response.data)

    def test_install_pstparse_endpoint(self) -> None:
        response = self.client.post("/api/install-pstparse-dotnet")
        self.assertIn(response.status_code, {200, 400})
        self.assertIn(b"pst_extractors", response.data)


if __name__ == "__main__":
    unittest.main()
