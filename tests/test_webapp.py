from __future__ import annotations

import io
import unittest

from dmark.webapp import create_app


class WebAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.client = self.app.test_client()

    def test_index_loads(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analyze PST Upload", response.data)

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
