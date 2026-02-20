from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path

from flask import Flask, Response, jsonify, request

from .parser import ParseError
from .pst_extract import (
    PstExtractError,
    extract_reports_from_pst,
    get_pst_backend_status,
    install_pstparse_dotnet_noninteractive,
)
from .reporting import analyze_inputs, analyze_uploaded_files


def create_app(
    max_upload_mb: int = 1024,
    min_fail_rate_alert: float = 0.02,
    min_messages_alert: int = 100,
    parse_workers: int = 0,
) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = max(1, max_upload_mb) * 1024 * 1024

    defaults = {
        "min_fail_rate_alert": min_fail_rate_alert,
        "min_messages_alert": min_messages_alert,
    }
    work_root = Path.cwd() / ".dmark_web_runs"
    work_root.mkdir(parents=True, exist_ok=True)
    jobs: dict[str, dict[str, object]] = {}
    jobs_lock = threading.Lock()

    def _create_job(initial_message: str) -> str:
        job_id = uuid.uuid4().hex
        with jobs_lock:
            jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "message": initial_message,
                "created_at": time.time(),
                "updated_at": time.time(),
            }
        return job_id

    def _update_job(job_id: str, **updates: object) -> None:
        with jobs_lock:
            current = jobs.get(job_id)
            if current is None:
                return
            current.update(updates)
            current["updated_at"] = time.time()

    def _get_job(job_id: str) -> dict[str, object] | None:
        with jobs_lock:
            current = jobs.get(job_id)
            if current is None:
                return None
            return dict(current)

    @app.get("/")
    def index() -> Response:
        html = (
            INDEX_HTML.replace("__DEFAULT_FAIL_RATE__", str(min_fail_rate_alert))
            .replace("__DEFAULT_MIN_MESSAGES__", str(min_messages_alert))
            .replace("__MAX_UPLOAD_MB__", str(max_upload_mb))
        )
        return Response(html, mimetype="text/html")

    @app.get("/api/ping")
    def ping():
        return jsonify({"ok": True})

    @app.get("/api/capabilities")
    def capabilities():
        return jsonify({"pst_extractors": get_pst_backend_status()})

    @app.post("/api/install-pstparse-dotnet")
    def install_pstparse_dotnet():
        ok, message = install_pstparse_dotnet_noninteractive()
        status = get_pst_backend_status()
        if ok:
            return jsonify({"ok": True, "message": message, "pst_extractors": status})
        return (
            jsonify({"ok": False, "message": message, "pst_extractors": status}),
            400,
        )

    @app.post("/api/analyze-path")
    def analyze_path():
        data = _request_data()
        raw_path = str(data.get("path", "")).strip()
        if not raw_path:
            return jsonify({"error": "Missing required field: path"}), 400

        try:
            result = analyze_inputs(
                inputs=[Path(raw_path)],
                min_fail_rate_alert=_float_value(
                    data.get("min_fail_rate_alert"),
                    defaults["min_fail_rate_alert"],
                ),
                min_messages_alert=_int_value(
                    data.get("min_messages_alert"),
                    defaults["min_messages_alert"],
                ),
                stop_on_error=False,
                resolve_source_ips=True,
                resolve_dns_records=True,
                parse_workers=parse_workers,
            )
        except ParseError as exc:
            return jsonify({"error": str(exc)}), 400

        return jsonify(result)

    @app.post("/api/analyze-upload")
    def analyze_upload():
        uploaded = request.files.getlist("files")
        if not uploaded:
            return jsonify({"error": "No uploaded files were provided."}), 400

        payloads = []
        for index, item in enumerate(uploaded, start=1):
            filename = (item.filename or f"upload-{index}.bin").strip()
            payloads.append((filename, item.read()))

        data = _request_data()
        try:
            result = analyze_uploaded_files(
                files=payloads,
                min_fail_rate_alert=_float_value(
                    data.get("min_fail_rate_alert"),
                    defaults["min_fail_rate_alert"],
                ),
                min_messages_alert=_int_value(
                    data.get("min_messages_alert"),
                    defaults["min_messages_alert"],
                ),
                stop_on_error=False,
                resolve_source_ips=True,
                resolve_dns_records=True,
                parse_workers=parse_workers,
            )
        except ParseError as exc:
            return jsonify({"error": str(exc)}), 400

        return jsonify(result)

    @app.post("/api/analyze-pst-upload")
    def analyze_pst_upload():
        uploaded = request.files.get("pst_file")
        if uploaded is None:
            return jsonify({"error": "No PST file was provided."}), 400

        filename = (uploaded.filename or "").strip().lower()
        if not filename.endswith(".pst"):
            return jsonify({"error": "Uploaded file must end in .pst"}), 400

        session_dir = work_root / f"run_{uuid.uuid4().hex}"
        extracted_dir = session_dir / "extracted"
        session_dir.mkdir(parents=True, exist_ok=True)
        extracted_dir.mkdir(parents=True, exist_ok=True)

        pst_path = session_dir / "input.pst"
        uploaded.save(pst_path)

        data = _request_data()
        engine = str(data.get("engine", "auto")).strip().lower()
        if engine not in {"auto", "pypff", "readpst", "pstparse-dotnet"}:
            engine = "auto"

        min_fail = _float_value(
            data.get("min_fail_rate_alert"),
            defaults["min_fail_rate_alert"],
        )
        min_messages = _int_value(
            data.get("min_messages_alert"),
            defaults["min_messages_alert"],
        )

        job_id = _create_job("Queued PST processing job.")

        def _run_job() -> None:
            _update_job(job_id, status="extracting", message="Extracting DMARC attachments from PST...")
            try:
                extracted_files, engine_used = extract_reports_from_pst(
                    pst_path=pst_path,
                    out_dir=extracted_dir,
                    engine=engine,
                )
                _update_job(
                    job_id,
                    status="analyzing",
                    message=(
                        "Analyzing extracted reports "
                        f"({len(extracted_files)} files)..."
                    ),
                )

                def _analysis_progress(event: dict[str, object]) -> None:
                    phase = str(event.get("phase", ""))
                    if phase == "tuning":
                        _update_job(
                            job_id,
                            status="analyzing",
                            message=str(event.get("message", "Auto-tuning parser workers...")),
                        )
                        return

                    processed = int(event.get("processed", 0))
                    total = int(event.get("total", 0))
                    parse_errors = int(event.get("parse_errors", 0))

                    if phase == "parse":
                        workers = int(event.get("workers", 0))
                        worker_suffix = f" using {workers} workers" if workers > 1 else ""
                        _update_job(
                            job_id,
                            status="analyzing",
                            message=(
                                "Parsing extracted reports: "
                                f"{processed}/{total} files "
                                f"({parse_errors} parse errors){worker_suffix}"
                            ),
                        )
                    elif phase == "dedupe":
                        _update_job(
                            job_id,
                            status="analyzing",
                            message=(
                                "Deduplicating parsed reports: "
                                f"{processed} valid reports"
                            ),
                        )
                    elif phase == "analyze":
                        _update_job(
                            job_id,
                            status="analyzing",
                            message=(
                                "Computing domain summaries: "
                                f"{processed} unique reports"
                            ),
                        )

                result = analyze_inputs(
                    inputs=[extracted_dir],
                    min_fail_rate_alert=min_fail,
                    min_messages_alert=min_messages,
                    stop_on_error=False,
                    resolve_source_ips=True,
                    resolve_dns_records=True,
                    parse_workers=parse_workers,
                    progress_callback=_analysis_progress,
                )
                result["pst"] = {
                    "engine_used": engine_used,
                    "extracted_files": len(extracted_files),
                    "run_dir": str(session_dir),
                }
                _update_job(
                    job_id,
                    status="complete",
                    message="PST processing complete.",
                    result=result,
                )
            except (PstExtractError, ParseError, Exception) as exc:
                _update_job(
                    job_id,
                    status="error",
                    message="PST processing failed.",
                    error=str(exc),
                )

        threading.Thread(target=_run_job, daemon=True).start()
        return (
            jsonify(
                {
                    "job_id": job_id,
                    "status": "queued",
                    "message": "PST upload accepted. Processing started.",
                }
            ),
            202,
        )

    @app.get("/api/pst-job/<job_id>")
    def pst_job(job_id: str):
        job = _get_job(job_id)
        if job is None:
            return jsonify({"error": "Job not found."}), 404
        return jsonify(job)

    @app.errorhandler(413)
    def payload_too_large(_):
        return (
            jsonify(
                {
                    "error": (
                        "Upload too large for current server limit. "
                        f"Restart with a bigger --max-upload-mb (current {max_upload_mb})."
                    )
                }
            ),
            413,
        )

    return app


def _request_data() -> dict[str, object]:
    data: dict[str, object] = {}
    if request.is_json:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            data.update(payload)
    if request.form:
        data.update(request.form.to_dict())
    return data


def _float_value(value: object, default: float) -> float:
    if value is None:
        return default
    try:
        parsed = float(value)
        if parsed < 0:
            return default
        return parsed
    except (TypeError, ValueError):
        return default


def _int_value(value: object, default: int) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
        if parsed < 1:
            return default
        return parsed
    except (TypeError, ValueError):
        return default


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>dmark Web UI</title>
  <style>
    :root {
      --bg-1: #f2f7f4;
      --bg-2: #fff6e8;
      --ink: #11201f;
      --muted: #536462;
      --card: rgba(255, 255, 255, 0.82);
      --line: rgba(17, 32, 31, 0.15);
      --accent: #0f8b7e;
      --accent-strong: #04524a;
      --warn: #c75b39;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Aptos", "Segoe UI", "Trebuchet MS", sans-serif;
      color: var(--ink);
      background: radial-gradient(circle at 8% 12%, #c9ece8 0%, transparent 40%),
                  radial-gradient(circle at 92% 88%, #ffe3bb 0%, transparent 45%),
                  linear-gradient(145deg, var(--bg-1), var(--bg-2));
      min-height: 100vh;
    }
    .wrap {
      width: 100%;
      max-width: none;
      margin: 0;
      padding: clamp(12px, 2vw, 24px);
    }
    .hero, .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      backdrop-filter: blur(7px);
      animation: rise 420ms ease-out both;
    }
    .hero { padding: 24px; margin-bottom: 16px; }
    h1 {
      margin: 0 0 8px 0;
      font-family: "Bahnschrift", "Arial Narrow", sans-serif;
      letter-spacing: 0.4px;
      font-size: clamp(1.5rem, 2.4vw, 2.2rem);
    }
    .sub { color: var(--muted); margin: 0; line-height: 1.5; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 16px;
      margin-bottom: 16px;
    }
    .card { padding: 16px; }
    .card h2 {
      margin: 0 0 10px 0;
      font-size: 1.05rem;
      font-family: "Bahnschrift", "Arial Narrow", sans-serif;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    label {
      display: block;
      margin: 10px 0 6px;
      font-size: 0.92rem;
      color: var(--muted);
    }
    input[type="text"], input[type="number"], input[type="file"], select {
      width: 100%;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: #ffffff;
      color: var(--ink);
      font: inherit;
    }
    .controls {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    button {
      margin-top: 12px;
      border: 0;
      border-radius: 12px;
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      color: #fff;
      padding: 10px 14px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      transition: transform 120ms ease, box-shadow 120ms ease;
      box-shadow: 0 6px 18px rgba(15, 139, 126, 0.25);
    }
    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 10px 22px rgba(15, 139, 126, 0.32);
    }
    .result { padding: 16px; }
    .status {
      margin-bottom: 10px;
      color: var(--muted);
      font-size: 0.95rem;
      min-height: 1.2rem;
    }
    .error { color: var(--warn); font-weight: 700; }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
      gap: 10px;
      margin: 12px 0;
    }
    .metric {
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
    }
    .metric .k {
      font-size: 0.78rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .metric .v { margin-top: 4px; font-size: 1.1rem; font-weight: 700; }
    table {
      width: max-content;
      min-width: 100%;
      table-layout: auto;
      border-collapse: collapse;
      background: #fff;
    }
    .table-container {
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: auto;
      max-height: 560px;
      background: #fff;
    }
    .trends {
      margin-top: 14px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 12px;
    }
    .trend-card {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
      padding: 10px;
    }
    .trend-card h3 {
      margin: 0 0 8px 0;
      font-size: 0.95rem;
      font-family: "Bahnschrift", "Arial Narrow", sans-serif;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .trend-chart {
      margin-bottom: 10px;
    }
    .trend-chart:last-child {
      margin-bottom: 0;
    }
    .trend-chart .label {
      font-size: 0.82rem;
      color: var(--muted);
      margin-bottom: 4px;
    }
    .sparkline {
      width: 100%;
      height: 120px;
      display: block;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: linear-gradient(180deg, rgba(15, 139, 126, 0.06), rgba(15, 139, 126, 0));
    }
    .sparkline.fail {
      background: linear-gradient(180deg, rgba(199, 91, 57, 0.08), rgba(199, 91, 57, 0));
    }
    .trend-meta {
      margin-top: 4px;
      display: flex;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
      font-size: 0.78rem;
      color: var(--muted);
    }
    th, td {
      border-bottom: 1px solid var(--line);
      text-align: left;
      padding: 8px 10px;
      font-size: 0.9rem;
      vertical-align: top;
      white-space: normal;
      overflow-wrap: anywhere;
    }
    th {
      position: sticky;
      top: 0;
      background: #edf7f6;
      z-index: 1;
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
    }
    td.domain-col {
      white-space: normal;
      min-width: 200px;
      overflow-wrap: anywhere;
    }
    td.sources-col {
      white-space: normal;
      min-width: 280px;
      line-height: 1.35;
    }
    td.health-col {
      white-space: normal;
      min-width: 240px;
      line-height: 1.3;
    }
    td.drivers-col {
      white-space: normal;
      min-width: 320px;
      line-height: 1.35;
    }
    td.auth-col {
      white-space: normal;
      min-width: 190px;
      line-height: 1.35;
    }
    td.impact-col {
      white-space: normal;
      min-width: 320px;
      line-height: 1.35;
    }
    td.issues-col {
      white-space: normal;
      min-width: 360px;
      line-height: 1.4;
    }
    td.actions-col {
      white-space: normal;
      min-width: 340px;
      line-height: 1.4;
    }
    th:nth-child(1), td:nth-child(1) { min-width: 200px; }
    th:nth-child(2), td:nth-child(2) { min-width: 90px; }
    th:nth-child(3), td:nth-child(3) { min-width: 170px; }
    th:nth-child(4), td:nth-child(4) { min-width: 240px; }
    th:nth-child(5), td:nth-child(5) { min-width: 320px; }
    th:nth-child(6), td:nth-child(6) { min-width: 280px; }
    th:nth-child(7), td:nth-child(7) { min-width: 110px; }
    th:nth-child(8), td:nth-child(8) { min-width: 110px; }
    th:nth-child(9), td:nth-child(9) { min-width: 190px; }
    th:nth-child(10), td:nth-child(10) { min-width: 190px; }
    th:nth-child(11), td:nth-child(11) { min-width: 320px; }
    th:nth-child(12), td:nth-child(12) { min-width: 280px; }
    th:nth-child(13), td:nth-child(13) { min-width: 280px; }
    th:nth-child(14), td:nth-child(14) { min-width: 360px; }
    th:nth-child(15), td:nth-child(15) { min-width: 340px; }
    .mini {
      color: var(--muted);
      font-size: 0.8rem;
      margin-top: 4px;
    }
    .mono { font-family: Consolas, "Courier New", monospace; font-size: 0.83rem; }
    .stack > div { margin-bottom: 4px; }
    .stack > div:last-child { margin-bottom: 0; }
    .sev {
      display: inline-block;
      border-radius: 999px;
      padding: 1px 8px;
      margin-right: 6px;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #fff;
      background: #5f6d6b;
    }
    .sev-high, .sev-critical { background: #b6402a; }
    .sev-medium { background: #9a6a11; }
    .sev-low, .sev-info { background: #587775; }
    .conf {
      color: var(--muted);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-left: 2px;
    }
    .hint { color: var(--muted); font-size: 0.86rem; margin-top: 8px; }
    @keyframes rise {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>dmark: DMARC Report Analyzer</h1>
      <p class="sub">Analyze DMARC reports by local path, by direct XML upload, or by PST upload. Upload size limit: <strong>__MAX_UPLOAD_MB__ MB</strong>.</p>
    </section>

    <section class="grid">
      <form id="pathForm" class="card">
        <h2>Analyze Local Path</h2>
        <label for="path">Folder or file path</label>
        <input id="path" name="path" type="text" placeholder="C:\\reports\\dmarc" required />
        <div class="controls">
          <div>
            <label for="pathFail">Min fail rate alert</label>
            <input id="pathFail" name="min_fail_rate_alert" type="number" min="0" step="0.001" value="__DEFAULT_FAIL_RATE__" />
          </div>
          <div>
            <label for="pathMinMessages">Min messages alert</label>
            <input id="pathMinMessages" name="min_messages_alert" type="number" min="1" step="1" value="__DEFAULT_MIN_MESSAGES__" />
          </div>
        </div>
        <button type="submit">Analyze Path</button>
        <p class="hint">Best for very large datasets because files stay on disk.</p>
      </form>

      <form id="uploadForm" class="card" enctype="multipart/form-data">
        <h2>Analyze XML Upload</h2>
        <label for="files">Report files (.xml / .xml.gz)</label>
        <input id="files" name="files" type="file" multiple required />
        <div class="controls">
          <div>
            <label for="uploadFail">Min fail rate alert</label>
            <input id="uploadFail" name="min_fail_rate_alert" type="number" min="0" step="0.001" value="__DEFAULT_FAIL_RATE__" />
          </div>
          <div>
            <label for="uploadMinMessages">Min messages alert</label>
            <input id="uploadMinMessages" name="min_messages_alert" type="number" min="1" step="1" value="__DEFAULT_MIN_MESSAGES__" />
          </div>
        </div>
        <button type="submit">Analyze Upload</button>
        <p class="hint">Useful for spot-checks.</p>
      </form>

      <form id="pstForm" class="card" enctype="multipart/form-data">
        <h2>Analyze PST Upload</h2>
        <label for="pstFile">PST file</label>
        <input id="pstFile" name="pst_file" type="file" accept=".pst" required />
        <label for="pstEngine">Extraction engine</label>
        <select id="pstEngine" name="engine">
          <option value="auto">auto (recommended)</option>
          <option value="pypff">pypff only</option>
          <option value="readpst">readpst only</option>
          <option value="pstparse-dotnet">pstparse-dotnet only</option>
        </select>
        <div class="controls">
          <div>
            <label for="pstFail">Min fail rate alert</label>
            <input id="pstFail" name="min_fail_rate_alert" type="number" min="0" step="0.001" value="__DEFAULT_FAIL_RATE__" />
          </div>
          <div>
            <label for="pstMinMessages">Min messages alert</label>
            <input id="pstMinMessages" name="min_messages_alert" type="number" min="1" step="1" value="__DEFAULT_MIN_MESSAGES__" />
          </div>
        </div>
        <button type="submit">Upload PST And Analyze</button>
        <button id="installPstparseBtn" type="button">Install PSTParse .NET helper</button>
        <p class="hint">This extracts DMARC report attachments from the uploaded PST, then analyzes them.</p>
      </form>
    </section>

    <section class="card result">
      <div id="status" class="status">Ready.</div>
      <div id="metrics" class="metrics"></div>
      <div id="tableWrap"></div>
      <div id="trendWrap" class="trends"></div>
    </section>
  </div>

  <script>
    const statusEl = document.getElementById("status");
    const metricsEl = document.getElementById("metrics");
    const tableWrapEl = document.getElementById("tableWrap");
    const trendWrapEl = document.getElementById("trendWrap");

    function setStatus(message, isError = false) {
      statusEl.textContent = message;
      statusEl.className = isError ? "status error" : "status";
    }

    function fmtPct(value) {
      const n = Number(value || 0);
      return (n * 100).toFixed(2) + "%";
    }

    function esc(value) {
      return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function renderMetrics(data) {
      const cards = [
        ["Files Scanned", data.files_scanned || 0],
        ["Files Parsed", data.files_parsed || 0],
        ["Parse Errors", data.parse_errors || 0],
        ["Duplicates", data.duplicate_reports_skipped || 0],
        ["Domains", (data.domains || []).length]
      ];

      if (data.pst) {
        cards.push(["PST Extracted", data.pst.extracted_files || 0]);
      }

      metricsEl.innerHTML = cards.map(([k, v]) =>
        `<div class="metric"><div class="k">${k}</div><div class="v">${v}</div></div>`
      ).join("");
    }

    function severityClass(severity) {
      const value = String(severity || "low").toLowerCase();
      if (value === "critical" || value === "high") return "sev sev-high";
      if (value === "medium") return "sev sev-medium";
      return "sev sev-low";
    }

    function _chartSeriesPoints(values, width, height, pad, maxOverride = null) {
      if (!values.length) return "";
      const maxRaw = maxOverride == null ? Math.max(...values) : Number(maxOverride || 0);
      const min = 0;
      const max = maxRaw <= min ? (min + 1) : maxRaw;
      return values.map((value, index) => {
        const x = pad + (index * (width - pad * 2)) / Math.max(1, values.length - 1);
        const y = height - pad - ((Number(value || 0) - min) / (max - min)) * (height - pad * 2);
        return `${x.toFixed(2)},${y.toFixed(2)}`;
      }).join(" ");
    }

    function _buildStackedVolumeChart(series) {
      if (!Array.isArray(series) || !series.length) {
        return "<div class='mini'>No time-series points available.</div>";
      }
      const width = 760;
      const height = 170;
      const pad = 18;
      const totalValues = series.map((row) => Number(row.messages_total || 0));
      const maxTotal = Math.max(1, ...totalValues);
      const step = (width - pad * 2) / Math.max(1, series.length);
      const barWidth = Math.max(1, step * 0.75);
      const scale = (height - pad * 2) / maxTotal;
      let rects = "";

      series.forEach((row, index) => {
        const approved = Number(row.approved_messages || 0);
        const noise = Number(row.noise_messages || 0);
        const pending = Number(row.pending_review_messages || 0);
        const x = pad + (index * step) + Math.max(0, (step - barWidth) / 2);
        let y = height - pad;
        [
          { value: approved, color: "#3a9a6b" },
          { value: noise, color: "#9aa4ab" },
          { value: pending, color: "#de8a3a" },
        ].forEach((segment) => {
          const rawHeight = Math.max(0, segment.value * scale);
          const h = rawHeight > 0 ? Math.max(rawHeight, 0.8) : 0;
          if (h <= 0) return;
          y -= h;
          rects += `<rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${barWidth.toFixed(2)}" height="${h.toFixed(2)}" fill="${segment.color}" opacity="0.95" />`;
        });
      });

      const labels = series.map((row) => String(row.date || ""));
      const startLabel = labels[0] || "-";
      const endLabel = labels[labels.length - 1] || "-";
      const latest = series[series.length - 1] || {};
      const avg = totalValues.reduce((sum, value) => sum + Number(value || 0), 0) / Math.max(1, totalValues.length);
      return `
        <svg class="sparkline" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-hidden="true">
          <line x1="${pad}" y1="${height - pad}" x2="${width - pad}" y2="${height - pad}" stroke="#c6d3d1" stroke-width="1" />
          ${rects}
        </svg>
        <div class="trend-meta">
          <span>${esc(startLabel)} -> ${esc(endLabel)}</span>
          <span>Latest total: ${Number(latest.messages_total || 0).toLocaleString()} msgs</span>
          <span>Avg/day: ${Math.round(avg).toLocaleString()} msgs</span>
          <span>Breakdown: approved ${Number(latest.approved_messages || 0).toLocaleString()}, noise ${Number(latest.noise_messages || 0).toLocaleString()}, pending ${Number(latest.pending_review_messages || 0).toLocaleString()}</span>
        </div>
        <div class="trend-meta">
          <span><strong style="color:#3a9a6b">Approved</strong></span>
          <span><strong style="color:#9aa4ab">Receiver-side noise</strong></span>
          <span><strong style="color:#de8a3a">Pending review / attack pressure</strong></span>
        </div>
      `;
    }

    function _buildSplitFailRateChart(series) {
      if (!Array.isArray(series) || !series.length) {
        return "<div class='mini'>No time-series points available.</div>";
      }
      const width = 760;
      const height = 160;
      const pad = 18;
      const labels = series.map((row) => String(row.date || ""));
      const legitValues = series.map((row) => Number(row.legitimate_fail_rate || 0) * 100);
      const attackValues = series.map((row) => Number(row.attack_pressure_fail_rate || 0) * 100);
      const maxValue = Math.max(1, ...legitValues, ...attackValues);
      const legitPoints = _chartSeriesPoints(legitValues, width, height, pad, maxValue);
      const attackPoints = _chartSeriesPoints(attackValues, width, height, pad, maxValue);
      const latestLegit = Number(legitValues[legitValues.length - 1] || 0);
      const latestAttack = Number(attackValues[attackValues.length - 1] || 0);
      const peakAttack = Math.max(...attackValues);
      const startLabel = labels[0] || "-";
      const endLabel = labels[labels.length - 1] || "-";
      return `
        <svg class="sparkline fail" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-hidden="true">
          <polyline fill="none" stroke="#b6402a" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" points="${legitPoints}" />
          <polyline fill="none" stroke="#7f8a90" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="6 4" points="${attackPoints}" />
        </svg>
        <div class="trend-meta">
          <span>${esc(startLabel)} -> ${esc(endLabel)}</span>
          <span>Latest legitimate fail: ${latestLegit.toFixed(2)}%</span>
          <span>Latest attack-pressure fail: ${latestAttack.toFixed(2)}%</span>
          <span>Peak attack-pressure fail: ${peakAttack.toFixed(2)}%</span>
        </div>
        <div class="trend-meta">
          <span><strong style="color:#b6402a">Solid red: legitimate fail rate</strong></span>
          <span><strong style="color:#7f8a90">Dashed gray: attack-pressure fail rate</strong></span>
        </div>
      `;
    }

    function renderTrendCharts(domains) {
      if (!Array.isArray(domains) || !domains.length) {
        trendWrapEl.innerHTML = "";
        return;
      }
      const cards = domains.map((domain) => {
        const series = Array.isArray(domain.time_series) ? domain.time_series.slice(-120) : [];
        if (!series.length) {
          return `
            <article class="trend-card">
              <h3>${esc(domain.domain || "unknown")} Trends</h3>
              <div class="mini">No date-bucketed trend data available in this run.</div>
            </article>
          `;
        }
        const volumeChart = _buildStackedVolumeChart(series);
        const failChart = _buildSplitFailRateChart(series);
        return `
          <article class="trend-card">
            <h3>${esc(domain.domain || "unknown")} Trends</h3>
            <div class="trend-chart">
              <div class="label">Daily Message Volume By Source Category (UTC buckets)</div>
              ${volumeChart}
            </div>
            <div class="trend-chart">
              <div class="label">Daily Fail Rates: Legitimate Risk vs Attack Pressure (UTC buckets)</div>
              ${failChart}
            </div>
          </article>
        `;
      }).join("");
      trendWrapEl.innerHTML = cards;
    }

    function renderDomains(data) {
      const domains = Array.isArray(data.domains) ? data.domains : [];
      if (!domains.length) {
        tableWrapEl.innerHTML = "<p class='hint'>No domain summaries were returned.</p>";
        trendWrapEl.innerHTML = "";
        return;
      }

      const rows = domains.map((d) => {
        const topSources = (d.top_failing_sources || []).slice(0, 3);
        const topSourcesHtml = topSources.length
          ? topSources.map((item) => {
              const host = item.hostname ? ` -> ${esc(item.hostname)}` : "";
              const sourceClass = item.classification && item.classification !== "unknown"
                ? `<div class="mini">${esc(item.classification.replace(/_/g, " "))} (${esc(item.classification_confidence || "low")})</div>`
                : "";
              const evidence = item.evidence_details || {};
              const topHeader = Array.isArray(evidence.top_header_from) && evidence.top_header_from.length
                ? String(evidence.top_header_from[0].name || "")
                : "";
              const topEnvelope = Array.isArray(evidence.top_envelope_from) && evidence.top_envelope_from.length
                ? String(evidence.top_envelope_from[0].name || "")
                : "";
              const topSelector = Array.isArray(evidence.top_dkim_selectors) && evidence.top_dkim_selectors.length
                ? String(evidence.top_dkim_selectors[0].name || "")
                : "";
              const topOverride = Array.isArray(evidence.top_override_reasons) && evidence.top_override_reasons.length
                ? String(evidence.top_override_reasons[0].name || "")
                : "";
              const topDisposition = Array.isArray(evidence.top_dispositions) && evidence.top_dispositions.length
                ? String(evidence.top_dispositions[0].name || "")
                : "";
              const investigationConf = item.investigation_confidence
                ? `<div class="mini">Investigation confidence: ${esc(item.investigation_confidence)}</div>`
                : "";
              const investigationNote = item.investigation_note
                ? `<div class="mini">${esc(item.investigation_note)}</div>`
                : "";
              const evidenceLine = (topHeader || topEnvelope || topSelector || topOverride)
                ? `<div class="mini">Hdr: ${esc(topHeader || "-")} | Env: ${esc(topEnvelope || "-")} | Sel: ${esc(topSelector || "-")} | Ovrd: ${esc(topOverride || "-")} | Disp: ${esc(topDisposition || "-")}</div>`
                : "";
              const evidenceDrawer = evidenceLine
                ? `<details class="mini"><summary>Evidence (aggregate record buckets)</summary>${evidenceLine}</details>`
                : "";
              return `<div class="mono">${esc(item.source_ip)} (${item.message_count})${host}${sourceClass}${investigationConf}${investigationNote}${evidenceDrawer}</div>`;
            }).join("")
          : "-";
        const healthCauses = (d.health_score_causes || []).slice(0, 3);
        const healthCausesHtml = healthCauses.length
          ? healthCauses.map((item) => `<div>${esc(item)}</div>`).join("")
          : "<div class='mini'>No score penalties observed.</div>";
        const issues = (d.issues || []).slice(0, 3);
        const issuesHtml = issues.length
          ? issues.map((issue) => {
              const sev = String(issue.severity || "low").toLowerCase();
              const cat = String(issue.category || "general").toLowerCase();
              const conf = String(issue.confidence || "low").toLowerCase();
              const sevClass = severityClass(sev);
              const title = esc(issue.title || "Issue");
              const categoryLabel = esc(cat.replace(/_/g, " "));
              const evidence = issue.evidence ? `<div class="mini">${esc(issue.evidence)}</div>` : "";
              const cause = issue.likely_cause ? `<div class="mini">Cause: ${esc(issue.likely_cause)}</div>` : "";
              const taxonomy = `<div class="mini">${categoryLabel} <span class="conf">${esc(conf)} confidence</span></div>`;
              return `<div><span class="${sevClass}">${esc(sev)}</span>${title}${taxonomy}${evidence}${cause}</div>`;
            }).join("")
          : "<div class='mini'>No diagnosed issues.</div>";
        const actionPlan = (d.action_plan || []).slice(0, 5);
        const actionPlanHtml = actionPlan.length
          ? actionPlan.map((step, index) => `<div>${index + 1}. ${esc(step)}</div>`).join("")
          : "-";
        const senderInventory = (d.sender_inventory || []).slice(0, 3);
        const senderInventoryHtml = senderInventory.length
          ? senderInventory.map((item) => {
              const flagNew = item.new_since_last_run ? "new" : "";
              const flagApproved = item.approved_sender ? "approved" : "";
              const flags = [flagApproved, flagNew].filter(Boolean).join(", ");
              const host = item.hostname ? ` -> ${esc(item.hostname)}` : "";
              const share = fmtPct(item.message_share_rate);
              const badge = flags ? `<div class="mini">${esc(flags)}</div>` : "";
              const legitStatusLabel = item.legit_status_label || item.legit_status || "pending_review";
              const cls = item.classification && item.classification !== "unknown"
                ? `<div class="mini">${esc(item.classification.replace(/_/g, " "))} / ${esc(legitStatusLabel)}</div>`
                : "";
              const actionLabel = item.suggested_action_label || item.suggested_action || "";
              const normalizedAction = String(actionLabel || "").toLowerCase().replace(/_/g, " ");
              const action = normalizedAction && normalizedAction !== "investigate"
                ? `<div class="mini">Action: ${esc(String(actionLabel).replace(/_/g, " "))}</div>`
                : "";
              return `<div class="mono">${esc(item.source_ip)} (${item.message_count}, ${share})${host}${badge}${cls}${action}</div>`;
            }).join("")
          : "-";
        const dkimAuthAlignHtml = `
          <div>Auth: <strong>${fmtPct(d.dkim_auth_pass_rate)}</strong></div>
          <div>Align: <strong>${fmtPct(d.dkim_aligned_pass_rate)}</strong></div>
          <div class="mini">Gap: ${fmtPct(d.dkim_alignment_gap_rate)}</div>
        `;
        const spfAuthAlignHtml = `
          <div>Auth: <strong>${fmtPct(d.spf_auth_pass_rate)}</strong></div>
          <div>Align: <strong>${fmtPct(d.spf_aligned_pass_rate)}</strong></div>
          <div class="mini">Gap: ${fmtPct(d.spf_alignment_gap_rate)}</div>
        `;
        const sim = d.policy_impact_simulation || {};
        const q100 = sim.quarantine_100 || {};
        const r100 = sim.reject_100 || {};
        const legitBasis = d.legitimate_basis || {};
        const dns = d.dns_diagnostics || {};
        const policyImpactHtml = `
          <div class="mini">Basis: ${esc(sim.basis || "all_observed_traffic")}</div>
          <div>quarantine pct=100: ${q100.estimated_legitimate_impacted_messages || 0} legit msgs (${fmtPct(q100.estimated_legitimate_impacted_rate)})</div>
          <div class="mini">All traffic: ${q100.estimated_impacted_messages || 0} msgs (${fmtPct(q100.estimated_impacted_rate)})</div>
          <div>reject pct=100: ${r100.estimated_legitimate_impacted_messages || 0} legit msgs (${fmtPct(r100.estimated_legitimate_impacted_rate)})</div>
          <div class="mini">All traffic: ${r100.estimated_impacted_messages || 0} msgs (${fmtPct(r100.estimated_impacted_rate)})</div>
        `;
        const policy = `${d.dominant_policy || "unknown"} (${(Number(d.policy_consistency || 0) * 100).toFixed(0)}%, pct ${Number(d.average_policy_pct || 100).toFixed(0)})`;
        const dnsStatusHtml = dns.enabled
          ? `<div class="mini">DNS: DMARC ${dns.dmarc_record_found ? "ok" : "missing"}, SPF ${dns.spf_record_found ? "ok" : "missing"}, M365 DKIM ${esc(dns.m365_dkim_status || "unknown")}</div>`
          : "";
        const trendTitle = esc(d.historical_trend_score_title || "Historical Trend Score");
        const trendDescription = d.historical_trend_score_description
          ? `<div class="mini">${esc(d.historical_trend_score_description)}</div>`
          : "";
        const aggregateEvidenceNote = d.aggregate_evidence_note
          ? `<div class="mini">${esc(d.aggregate_evidence_note)}</div>`
          : "";
        const health = `${d.historical_trend_score || d.health_score || 0} ${d.historical_trend_label || d.health_label || ""}`.trim();
        const deliverability = Number(d.deliverability_safety_score || 0).toFixed(0);
        const posture = Number(d.anti_spoofing_posture_score || 0).toFixed(0);
        const protectionScore = Number(d.protection_posture_score || d.anti_spoofing_posture_score || 0).toFixed(0);
        const protectionGrade = esc(d.protection_posture_grade || "-");
        const authCoverage = fmtPct(d.authentication_coverage_rate);
        const authCoverageDkim = fmtPct(d.authentication_coverage_dkim_rate);
        const authCoverageSpf = fmtPct(d.authentication_coverage_spf_rate);
        const attackPressureLabel = esc(d.attack_pressure_label || d.attack_pressure_level || "Unknown");
        const attackPressureRate = fmtPct(d.attack_pressure_fail_rate);
        const attackPressureCount = d.attack_pressure_fail_count || 0;
        const scoreConfidence = esc(d.score_confidence || "low");
        const readinessLabel = d.enforcement_readiness || "-";
        const readinessDetail = d.enforcement_readiness_detail ? `<div class="mini">${esc(d.enforcement_readiness_detail)}</div>` : "";
        const readinessBasis = d.readiness_gate && d.readiness_gate.basis ? `<div class="mini">Basis: ${esc(d.readiness_gate.basis)}</div>` : "";
        const healthSummary = d.health_score_summary ? `<div class="mini">${esc(d.health_score_summary)}</div>` : "";
        const receiverSideNote = d.receiver_side_security_relay_note
          ? `<div class="mini">${esc(d.receiver_side_security_relay_note)}</div>`
          : "";
        const safetyNote = d.deliverability_safety_note
          ? `<div class="mini">${esc(d.deliverability_safety_note)}</div>`
          : "";
        const attackPressureNote = d.attack_pressure_note
          ? `<div class="mini">${esc(d.attack_pressure_note)}</div>`
          : "";
        const senderSummary = d.sender_inventory_summary || {};
        const senderSummaryHtml = `
          <div class="mini">Approved: ${fmtPct(senderSummary.approved_rate)} (${senderSummary.approved_messages || 0} msgs)</div>
          <div class="mini">Noise excluded: ${fmtPct(senderSummary.noise_rate)} (${senderSummary.noise_messages || 0} msgs)</div>
          <div class="mini">Pending review: ${fmtPct(senderSummary.pending_review_rate)} (${senderSummary.pending_review_messages || 0} msgs)</div>
        `;
        const legitBasisDetail = `
          <div class="mini">Legit basis: ${esc(legitBasis.basis || "all_observed_traffic")}</div>
          <div class="mini">Coverage: ${fmtPct(legitBasis.coverage_rate)} (${legitBasis.messages_total || 0} msgs)</div>
          <div class="mini">Noise excluded: ${legitBasis.noise_messages_excluded || 0} msgs</div>
        `;

        return `
          <tr>
            <td class="mono domain-col">${esc(d.domain || "unknown")}</td>
            <td>${d.messages_total || 0}</td>
            <td>${esc(policy)}${dnsStatusHtml}</td>
            <td class="health-col">
              <div><strong>Protection posture: ${protectionGrade} (${protectionScore})</strong> <span class="mini">${scoreConfidence} confidence</span></div>
              <div class="mini">${trendTitle}: ${esc(health)}</div>
              <div class="mini">Deliverability safety: ${deliverability}</div>
              <div class="mini">Anti-spoofing posture: ${posture}</div>
              <div class="mini">Authentication coverage: ${authCoverage} (DKIM ${authCoverageDkim} / SPF ${authCoverageSpf})</div>
              <div class="mini">Attack pressure: ${attackPressureLabel} (${attackPressureRate}, ${attackPressureCount} fails)</div>
              ${trendDescription}
              ${aggregateEvidenceNote}
              ${healthSummary}
              ${safetyNote}
              ${attackPressureNote}
              ${receiverSideNote}
            </td>
            <td class="drivers-col stack">${healthCausesHtml}</td>
            <td><div>${esc(readinessLabel)}</div>${readinessDetail}${readinessBasis}${legitBasisDetail}</td>
            <td>${fmtPct(d.dmarc_pass_rate)}</td>
            <td>${fmtPct(d.dmarc_fail_rate)}</td>
            <td class="auth-col stack">${dkimAuthAlignHtml}</td>
            <td class="auth-col stack">${spfAuthAlignHtml}</td>
            <td class="impact-col stack">${policyImpactHtml}</td>
            <td class="sources-col stack">${senderSummaryHtml}${senderInventoryHtml}</td>
            <td class="sources-col stack">${topSourcesHtml}</td>
            <td class="issues-col stack">${issuesHtml}</td>
            <td class="actions-col stack">${actionPlanHtml}</td>
          </tr>
        `;
      }).join("");

      tableWrapEl.innerHTML = `
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Messages</th>
                <th>Policy</th>
                <th>Posture & Trend</th>
                <th>Trend Drivers</th>
                <th>Readiness</th>
                <th>DMARC Pass</th>
                <th>DMARC Fail</th>
                <th>DKIM Auth/Align</th>
                <th>SPF Auth/Align</th>
                <th>Policy Impact Simulator</th>
                <th>Top Senders</th>
                <th>Top Failing Sources</th>
                <th>Key Issues</th>
                <th>Action Plan</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
      renderTrendCharts(domains);
    }

    async function parsePayload(response) {
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        return await response.json();
      }
      const text = await response.text();
      return { error: text || "Request failed" };
    }

    async function handleResponse(response) {
      const payload = await parsePayload(response);
      if (!response.ok) {
        throw new Error(payload.error || "Request failed");
      }
      renderMetrics(payload);
      renderDomains(payload);
      if (payload.pst && payload.pst.engine_used) {
        setStatus(`Analysis complete. PST engine: ${payload.pst.engine_used}`);
      } else {
        setStatus("Analysis complete.");
      }
    }

    function sleep(ms) {
      return new Promise((resolve) => setTimeout(resolve, ms));
    }

    async function pollPstJob(jobId) {
      const startedAt = Date.now();
      while (true) {
        const response = await fetch(`/api/pst-job/${encodeURIComponent(jobId)}`);
        const payload = await parsePayload(response);
        if (!response.ok) {
          throw new Error(payload.error || "Could not fetch PST job status.");
        }

        const elapsed = Math.floor((Date.now() - startedAt) / 1000);
        const message = payload.message || "Working...";

        if (payload.status === "complete") {
          if (payload.result) {
            renderMetrics(payload.result);
            renderDomains(payload.result);
          }
          setStatus(`${message} (${elapsed}s)`);
          return;
        }

        if (payload.status === "error") {
          throw new Error(payload.error || message || "PST analysis failed.");
        }

        setStatus(`${message} (${elapsed}s)`);
        await sleep(1500);
      }
    }

    function resetOutput() {
      metricsEl.innerHTML = "";
      tableWrapEl.innerHTML = "";
      trendWrapEl.innerHTML = "";
    }

    async function loadCapabilities() {
      try {
        const response = await fetch("/api/capabilities");
        const payload = await parsePayload(response);
        if (!response.ok || !payload.pst_extractors) {
          return;
        }
        const caps = payload.pst_extractors;
        if (!caps.pypff && !caps.readpst && !caps.pstparse_dotnet) {
          setStatus("PST extraction backend missing: install pypff, readpst, or PSTParse .NET helper.", true);
        }
      } catch (_err) {
        // Keep default status text if capabilities check fails.
      }
    }

    document.getElementById("installPstparseBtn").addEventListener("click", async () => {
      setStatus("Building PSTParse .NET helper...");
      try {
        const response = await fetch("/api/install-pstparse-dotnet", { method: "POST" });
        const payload = await parsePayload(response);
        if (!response.ok) {
          throw new Error(payload.message || payload.error || "Install failed");
        }
        setStatus(payload.message || "PSTParse helper installed.");
        await loadCapabilities();
      } catch (err) {
        setStatus(err.message || "PSTParse install failed.", true);
      }
    });

    document.getElementById("pathForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      setStatus("Analyzing path...");
      resetOutput();

      const path = document.getElementById("path").value;
      const minFail = document.getElementById("pathFail").value;
      const minMessages = document.getElementById("pathMinMessages").value;

      try {
        const response = await fetch("/api/analyze-path", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path: path,
            min_fail_rate_alert: minFail,
            min_messages_alert: minMessages
          })
        });
        await handleResponse(response);
      } catch (err) {
        setStatus(err.message || "Analysis failed.", true);
      }
    });

    document.getElementById("uploadForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      setStatus("Uploading and analyzing XML files...");
      resetOutput();

      const fileInput = document.getElementById("files");
      if (!fileInput.files || !fileInput.files.length) {
        setStatus("Select at least one file.", true);
        return;
      }

      const form = new FormData();
      for (const file of fileInput.files) {
        form.append("files", file, file.name);
      }
      form.append("min_fail_rate_alert", document.getElementById("uploadFail").value);
      form.append("min_messages_alert", document.getElementById("uploadMinMessages").value);

      try {
        const response = await fetch("/api/analyze-upload", {
          method: "POST",
          body: form
        });
        await handleResponse(response);
      } catch (err) {
        setStatus(err.message || "Upload analysis failed.", true);
      }
    });

    document.getElementById("pstForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      setStatus("Uploading PST and extracting DMARC reports...");
      resetOutput();

      const pstFileInput = document.getElementById("pstFile");
      if (!pstFileInput.files || !pstFileInput.files.length) {
        setStatus("Select a PST file.", true);
        return;
      }

      const form = new FormData();
      form.append("pst_file", pstFileInput.files[0], pstFileInput.files[0].name);
      form.append("engine", document.getElementById("pstEngine").value);
      form.append("min_fail_rate_alert", document.getElementById("pstFail").value);
      form.append("min_messages_alert", document.getElementById("pstMinMessages").value);

      try {
        const response = await fetch("/api/analyze-pst-upload", {
          method: "POST",
          body: form
        });
        const payload = await parsePayload(response);
        if (!response.ok) {
          throw new Error(payload.error || "PST analysis failed.");
        }
        if (!payload.job_id) {
          throw new Error("Server did not return a PST job id.");
        }
        setStatus(payload.message || "PST upload accepted.");
        await pollPstJob(payload.job_id);
      } catch (err) {
        setStatus(err.message || "PST analysis failed.", true);
      }
    });

    loadCapabilities();
  </script>
</body>
</html>
"""
