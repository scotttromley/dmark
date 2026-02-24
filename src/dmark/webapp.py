from __future__ import annotations

import logging
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from .parser import ParseError
from .pst_extract import (
    PstExtractError,
    extract_reports_from_pst,
    get_pst_backend_status,
    install_pstparse_dotnet_noninteractive,
)
from .reporting import analyze_inputs, analyze_uploaded_files

_LOG = logging.getLogger(__name__)


def create_app(
    max_upload_mb: int = 1024,
    min_fail_rate_alert: float = 0.02,
    min_messages_alert: int = 100,
    parse_workers: int = 0,
    job_ttl_seconds: int = 6 * 60 * 60,
    max_jobs: int = 500,
) -> Flask:
    effective_max_upload_mb = max(1, int(max_upload_mb))
    effective_job_ttl_seconds = max(0, int(job_ttl_seconds))
    effective_max_jobs = max(1, int(max_jobs))
    _pkg_dir = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(_pkg_dir / "templates"),
        static_folder=str(_pkg_dir / "static"),
    )
    app.config["MAX_CONTENT_LENGTH"] = effective_max_upload_mb * 1024 * 1024

    defaults = {
        "min_fail_rate_alert": min_fail_rate_alert,
        "min_messages_alert": min_messages_alert,
    }
    work_root = Path.cwd() / ".dmark_web_runs"
    work_root.mkdir(parents=True, exist_ok=True)
    jobs: dict[str, dict[str, object]] = {}
    jobs_lock = threading.Lock()
    terminal_job_statuses = {"complete", "error"}

    # Ensure parse_workers is at least 0.
    parse_workers = parse_workers if parse_workers >= 1 else 0

    def _cleanup_jobs_unlocked(now_epoch: float) -> None:
        if effective_job_ttl_seconds > 0:
            stale_cutoff = now_epoch - effective_job_ttl_seconds
            stale_job_ids = [
                job_id
                for job_id, state in jobs.items()
                if str(state.get("status", "")) in terminal_job_statuses
                and float(state.get("updated_at", 0.0)) < stale_cutoff
            ]
            for job_id in stale_job_ids:
                jobs.pop(job_id, None)
            if stale_job_ids:
                _LOG.debug("Cleaned up %d stale PST jobs", len(stale_job_ids))

        overflow = len(jobs) - effective_max_jobs
        if overflow <= 0:
            return
        candidates = sorted(
            jobs.items(),
            key=lambda item: (
                0 if str(item[1].get("status", "")) in terminal_job_statuses else 1,
                float(item[1].get("updated_at", 0.0)),
            ),
        )
        for job_id, _ in candidates[:overflow]:
            jobs.pop(job_id, None)
        _LOG.debug("Trimmed %d PST jobs to keep in-memory state bounded", overflow)

    def _create_job(initial_message: str) -> str:
        job_id = uuid.uuid4().hex
        now_epoch = time.time()
        with jobs_lock:
            _cleanup_jobs_unlocked(now_epoch)
            jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "message": initial_message,
                "created_at": now_epoch,
                "updated_at": now_epoch,
            }
        _LOG.info("Queued PST job %s", job_id)
        return job_id

    def _update_job(job_id: str, **updates: object) -> None:
        with jobs_lock:
            current = jobs.get(job_id)
            if current is None:
                return
            previous_status = str(current.get("status", ""))
            current.update(updates)
            current["updated_at"] = time.time()
            current_status = str(current.get("status", ""))
        if current_status != previous_status:
            _LOG.info(
                "PST job %s status changed %s -> %s",
                job_id,
                previous_status or "unknown",
                current_status or "unknown",
            )
        if current_status == "error":
            _LOG.error("PST job %s failed: %s", job_id, str(updates.get("error", "")))

    def _get_job(job_id: str) -> dict[str, object] | None:
        with jobs_lock:
            _cleanup_jobs_unlocked(time.time())
            current = jobs.get(job_id)
            if current is None:
                return None
            return dict(current)

    @app.get("/")
    def index() -> str:
        return render_template(
            "index.html",
            default_fail_rate=min_fail_rate_alert,
            default_min_messages=min_messages_alert,
            max_upload_mb=effective_max_upload_mb,
        )

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
            _LOG.info("analyze-path rejected: missing path")
            return jsonify({"error": "Missing required field: path"}), 400

        requested_path = Path(raw_path)
        if not requested_path.exists():
            _LOG.info("analyze-path rejected: path not found (%s)", raw_path)
            return jsonify({"error": f"Path not found: {raw_path}"}), 400

        try:
            result = analyze_inputs(
                inputs=[requested_path],
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
            _LOG.info("analyze-path parse failure for %s: %s", raw_path, exc)
            return jsonify({"error": str(exc)}), 400

        _LOG.info(
            "analyze-path complete for %s: files_parsed=%s domains=%s",
            raw_path,
            result.get("files_parsed", 0),
            len(result.get("domains", [])) if isinstance(result.get("domains", []), list) else 0,
        )
        return jsonify(result)

    @app.post("/api/analyze-upload")
    def analyze_upload():
        uploaded = request.files.getlist("files")
        if not uploaded:
            _LOG.info("analyze-upload rejected: no files")
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
            _LOG.info("analyze-upload parse failure: %s", exc)
            return jsonify({"error": str(exc)}), 400

        _LOG.info(
            "analyze-upload complete: files=%s parsed=%s domains=%s",
            len(payloads),
            result.get("files_parsed", 0),
            len(result.get("domains", [])) if isinstance(result.get("domains", []), list) else 0,
        )
        return jsonify(result)

    @app.post("/api/analyze-pst-upload")
    def analyze_pst_upload():
        uploaded = request.files.get("pst_file")
        if uploaded is None:
            _LOG.info("analyze-pst-upload rejected: missing pst_file")
            return jsonify({"error": "No PST file was provided."}), 400

        filename = (uploaded.filename or "").strip().lower()
        if not filename.endswith(".pst"):
            _LOG.info("analyze-pst-upload rejected: invalid extension (%s)", filename)
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
            except (PstExtractError, ParseError) as exc:
                _update_job(
                    job_id,
                    status="error",
                    message="PST processing failed.",
                    error=str(exc),
                )
            except Exception as exc:
                _LOG.exception("Unexpected PST processing failure for job %s", job_id)
                _update_job(
                    job_id,
                    status="error",
                    message="PST processing failed.",
                    error=str(exc),
                )

        threading.Thread(target=_run_job, daemon=True).start()
        _LOG.info("Accepted PST upload job %s (engine=%s)", job_id, engine)
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
                            "Restart with a bigger --max-upload-mb "
                            f"(current {effective_max_upload_mb})."
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
