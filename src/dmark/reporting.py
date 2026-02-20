from __future__ import annotations

import json
import os
import platform
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Callable

from .analyzer import analyze_reports, report_set_to_unique_reports
from .parser import ParseError, parse_report_bytes, parse_report_file

ProgressCallback = Callable[[dict[str, object]], None]
_AUTOTUNE_MIN_FILES = 200
_AUTOTUNE_SAMPLE_SIZE = 120


def analyze_inputs(
    inputs: list[Path],
    min_fail_rate_alert: float = 0.02,
    min_messages_alert: int = 100,
    stop_on_error: bool = False,
    resolve_source_ips: bool = False,
    resolve_dns_records: bool = False,
    parse_workers: int | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, object]:
    candidates = collect_candidates(inputs)
    if not candidates:
        raise ParseError("No candidate report files found.")

    parsed, parse_errors = _parse_paths(
        candidates=candidates,
        stop_on_error=stop_on_error,
        parse_workers=parse_workers,
        progress_callback=progress_callback,
    )

    if not parsed:
        raise ParseError("No valid DMARC report files were parsed.")

    _emit_progress(
        progress_callback,
        phase="dedupe",
        processed=len(parsed),
        total=len(candidates),
        parse_errors=parse_errors,
    )
    return _build_output(
        reports=parsed,
        files_scanned=len(candidates),
        files_parsed=len(parsed),
        parse_errors=parse_errors,
        min_fail_rate_alert=min_fail_rate_alert,
        min_messages_alert=min_messages_alert,
        resolve_source_ips=resolve_source_ips,
        resolve_dns_records=resolve_dns_records,
        progress_callback=progress_callback,
    )


def analyze_uploaded_files(
    files: list[tuple[str, bytes]],
    min_fail_rate_alert: float = 0.02,
    min_messages_alert: int = 100,
    stop_on_error: bool = False,
    resolve_source_ips: bool = False,
    resolve_dns_records: bool = False,
    parse_workers: int | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, object]:
    accepted = [item for item in files if _is_candidate_name(item[0])]
    if not accepted:
        raise ParseError("No candidate report files found in upload.")

    parsed, parse_errors = _parse_uploads(
        accepted=accepted,
        stop_on_error=stop_on_error,
        parse_workers=parse_workers,
        progress_callback=progress_callback,
    )

    if not parsed:
        raise ParseError("No valid DMARC report files were parsed from uploads.")

    _emit_progress(
        progress_callback,
        phase="dedupe",
        processed=len(parsed),
        total=len(accepted),
        parse_errors=parse_errors,
    )
    return _build_output(
        reports=parsed,
        files_scanned=len(accepted),
        files_parsed=len(parsed),
        parse_errors=parse_errors,
        min_fail_rate_alert=min_fail_rate_alert,
        min_messages_alert=min_messages_alert,
        resolve_source_ips=resolve_source_ips,
        resolve_dns_records=resolve_dns_records,
        progress_callback=progress_callback,
    )


def collect_candidates(inputs: list[Path]) -> list[Path]:
    candidates: list[Path] = []
    for input_path in inputs:
        if not input_path.exists():
            continue
        if input_path.is_file():
            if _is_candidate_path(input_path):
                candidates.append(input_path)
            continue
        for child in input_path.rglob("*"):
            if child.is_file() and _is_candidate_path(child):
                candidates.append(child)
    return sorted(set(candidates))


def _is_candidate_path(path: Path) -> bool:
    return _is_candidate_name(path.name)


def _is_candidate_name(filename: str) -> bool:
    name = (filename or "").lower()
    return name.endswith(".xml") or name.endswith(".xml.gz") or name.endswith(".gz")


def _build_output(
    reports,
    files_scanned: int,
    files_parsed: int,
    parse_errors: int,
    min_fail_rate_alert: float,
    min_messages_alert: int,
    resolve_source_ips: bool = False,
    resolve_dns_records: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, object]:
    unique_reports, duplicates_skipped = report_set_to_unique_reports(reports)
    _emit_progress(
        progress_callback,
        phase="analyze",
        processed=0,
        total=len(unique_reports),
        parse_errors=parse_errors,
    )
    summary_by_domain = analyze_reports(
        reports=unique_reports,
        min_fail_rate_alert=min_fail_rate_alert,
        min_messages_alert=min_messages_alert,
        progress_callback=(
            lambda event: _emit_progress(
                progress_callback,
                phase="analyze",
                processed=int(event.get("processed_reports", 0)),
                total=int(event.get("total_reports", len(unique_reports))),
                parse_errors=parse_errors,
            )
        ),
    )
    sender_history = _load_sender_history()
    approved_sender_map = _load_approved_sender_map()
    domains_payload: list[dict[str, object]] = []
    updated_sender_history = dict(sender_history)
    for domain_name, summary in sorted(summary_by_domain.items()):
        previous_senders = set(sender_history.get(domain_name, []))
        approved_senders = set(approved_sender_map.get(domain_name, []))
        domains_payload.append(
            summary.to_dict(
                resolve_source_ips=resolve_source_ips,
                resolve_dns_records=resolve_dns_records,
                previous_sender_history=previous_senders,
                approved_senders=approved_senders,
            )
        )
        updated_sender_history[domain_name] = sorted(set(summary.source_message_counts.keys()))
    _save_sender_history(updated_sender_history)

    return {
        "files_scanned": files_scanned,
        "files_parsed": files_parsed,
        "parse_errors": parse_errors,
        "duplicate_reports_skipped": duplicates_skipped,
        "domains": domains_payload,
        "approved_sender_config_detected": bool(approved_sender_map),
    }


def _should_emit_progress(index: int, total: int) -> bool:
    if index == total:
        return True
    if total <= 200:
        return index % 10 == 0
    return index % 50 == 0


def _emit_progress(callback: ProgressCallback | None, **payload: object) -> None:
    if callback is not None:
        callback(dict(payload))


def _sender_history_cache_path() -> Path:
    return Path(__file__).resolve().parents[2] / ".dmark_cache" / "sender_history.json"


def _approved_senders_config_path() -> Path:
    return Path(__file__).resolve().parents[2] / ".dmark_cache" / "approved_senders.json"


def _load_sender_history() -> dict[str, list[str]]:
    path = _sender_history_cache_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    normalized: dict[str, list[str]] = {}
    for domain_name, entries in payload.items():
        if not isinstance(domain_name, str) or not isinstance(entries, list):
            continue
        values = [str(item).strip() for item in entries if str(item).strip()]
        normalized[domain_name.strip().lower()] = sorted(set(values))
    return normalized


def _save_sender_history(payload: dict[str, list[str]]) -> None:
    path = _sender_history_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _load_approved_sender_map() -> dict[str, list[str]]:
    path = _approved_senders_config_path()
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    source = raw
    if isinstance(raw, dict) and isinstance(raw.get("domains"), dict):
        source = raw["domains"]
    if not isinstance(source, dict):
        return {}
    normalized: dict[str, list[str]] = {}
    for domain_name, entries in source.items():
        if not isinstance(domain_name, str) or not isinstance(entries, list):
            continue
        values = [str(item).strip() for item in entries if str(item).strip()]
        normalized[domain_name.strip().lower()] = sorted(set(values))
    return normalized


def _default_parse_workers() -> int:
    cores = os.cpu_count() or 4
    return max(1, min(16, cores))


def _normalize_parse_workers(
    parse_workers: int | None,
    candidates: list[Path] | None = None,
    progress_callback: ProgressCallback | None = None,
) -> int:
    if parse_workers is None or parse_workers <= 0:
        tuned = _get_tuned_workers()
        if tuned is not None:
            return tuned
        if candidates is not None and len(candidates) >= _AUTOTUNE_MIN_FILES:
            tuned = _autotune_parse_workers(candidates, progress_callback)
            if tuned is not None:
                _save_tuned_workers(tuned)
                return tuned
        return _default_parse_workers()
    return max(1, parse_workers)


def _parse_paths(
    candidates: list[Path],
    stop_on_error: bool,
    parse_workers: int | None,
    progress_callback: ProgressCallback | None,
) -> tuple[list, int]:
    workers = _normalize_parse_workers(
        parse_workers=parse_workers,
        candidates=candidates,
        progress_callback=progress_callback,
    )
    total = len(candidates)
    _emit_progress(
        progress_callback,
        phase="parse",
        processed=0,
        total=total,
        parse_errors=0,
        workers=workers,
    )
    if workers <= 1 or total <= 1:
        return _parse_paths_sequential(candidates, stop_on_error, progress_callback)
    return _parse_paths_parallel(candidates, stop_on_error, workers, progress_callback)


def _parse_uploads(
    accepted: list[tuple[str, bytes]],
    stop_on_error: bool,
    parse_workers: int | None,
    progress_callback: ProgressCallback | None,
) -> tuple[list, int]:
    workers = _normalize_parse_workers(parse_workers=parse_workers)
    total = len(accepted)
    _emit_progress(
        progress_callback,
        phase="parse",
        processed=0,
        total=total,
        parse_errors=0,
        workers=workers,
    )
    if workers <= 1 or total <= 1:
        return _parse_uploads_sequential(accepted, stop_on_error, progress_callback)
    return _parse_uploads_parallel(accepted, stop_on_error, workers, progress_callback)


def _parse_paths_sequential(
    candidates: list[Path],
    stop_on_error: bool,
    progress_callback: ProgressCallback | None,
) -> tuple[list, int]:
    parsed = []
    parse_errors = 0
    total = len(candidates)
    for index, path in enumerate(candidates, start=1):
        try:
            parsed.append(parse_report_file(path))
        except ParseError:
            parse_errors += 1
            if stop_on_error:
                raise
        if _should_emit_progress(index, total):
            _emit_progress(
                progress_callback,
                phase="parse",
                processed=index,
                total=total,
                parse_errors=parse_errors,
                workers=1,
            )
    return parsed, parse_errors


def _parse_uploads_sequential(
    accepted: list[tuple[str, bytes]],
    stop_on_error: bool,
    progress_callback: ProgressCallback | None,
) -> tuple[list, int]:
    parsed = []
    parse_errors = 0
    total = len(accepted)
    for index, (filename, payload) in enumerate(accepted, start=1):
        try:
            parsed.append(parse_report_bytes(payload, source_name=filename))
        except ParseError:
            parse_errors += 1
            if stop_on_error:
                raise
        if _should_emit_progress(index, total):
            _emit_progress(
                progress_callback,
                phase="parse",
                processed=index,
                total=total,
                parse_errors=parse_errors,
                workers=1,
            )
    return parsed, parse_errors


def _parse_paths_parallel(
    candidates: list[Path],
    stop_on_error: bool,
    workers: int,
    progress_callback: ProgressCallback | None,
) -> tuple[list, int]:
    parsed = []
    parse_errors = 0
    total = len(candidates)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending: set[Future] = {
            executor.submit(parse_report_file, path) for path in candidates
        }
        processed = 0
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                processed += 1
                try:
                    parsed.append(future.result())
                except ParseError:
                    parse_errors += 1
                    if stop_on_error:
                        for rest in pending:
                            rest.cancel()
                        raise
                except Exception as exc:
                    parse_errors += 1
                    if stop_on_error:
                        for rest in pending:
                            rest.cancel()
                        raise ParseError(f"Unexpected parse failure: {exc}") from exc
                if _should_emit_progress(processed, total):
                    _emit_progress(
                        progress_callback,
                        phase="parse",
                        processed=processed,
                        total=total,
                        parse_errors=parse_errors,
                        workers=workers,
                    )
    return parsed, parse_errors


def _parse_uploads_parallel(
    accepted: list[tuple[str, bytes]],
    stop_on_error: bool,
    workers: int,
    progress_callback: ProgressCallback | None,
) -> tuple[list, int]:
    parsed = []
    parse_errors = 0
    total = len(accepted)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending: set[Future] = {
            executor.submit(parse_report_bytes, payload, filename)
            for filename, payload in accepted
        }
        processed = 0
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                processed += 1
                try:
                    parsed.append(future.result())
                except ParseError:
                    parse_errors += 1
                    if stop_on_error:
                        for rest in pending:
                            rest.cancel()
                        raise
                except Exception as exc:
                    parse_errors += 1
                    if stop_on_error:
                        for rest in pending:
                            rest.cancel()
                        raise ParseError(f"Unexpected parse failure: {exc}") from exc
                if _should_emit_progress(processed, total):
                    _emit_progress(
                        progress_callback,
                        phase="parse",
                        processed=processed,
                        total=total,
                        parse_errors=parse_errors,
                        workers=workers,
                    )
    return parsed, parse_errors


def _autotune_parse_workers(
    candidates: list[Path],
    progress_callback: ProgressCallback | None,
) -> int | None:
    sample = candidates[: min(len(candidates), _AUTOTUNE_SAMPLE_SIZE)]
    worker_options = _worker_options_for_system()
    if len(worker_options) <= 1:
        return worker_options[0] if worker_options else None

    _emit_progress(
        progress_callback,
        phase="tuning",
        message=(
            f"Auto-tuning parse workers on {len(sample)} sample files "
            f"({len(worker_options)} trials)..."
        ),
    )

    timings: dict[int, float] = {}
    for worker_count in worker_options:
        started = time.perf_counter()
        if worker_count <= 1:
            for path in sample:
                try:
                    parse_report_file(path)
                except ParseError:
                    continue
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [executor.submit(parse_report_file, path) for path in sample]
                for future in futures:
                    try:
                        future.result()
                    except ParseError:
                        continue
                    except Exception:
                        continue
        timings[worker_count] = time.perf_counter() - started
        _emit_progress(
            progress_callback,
            phase="tuning",
            message=(
                f"Tuning trial complete: {worker_count} workers in "
                f"{timings[worker_count]:.2f}s"
            ),
        )

    if not timings:
        return None
    return min(timings.items(), key=lambda item: item[1])[0]


def _worker_options_for_system() -> list[int]:
    cores = os.cpu_count() or 4
    options = sorted(
        {
            1,
            max(2, cores // 4),
            max(4, cores // 2),
            min(cores, 16),
            min(cores, 24),
            min(cores, 32),
        }
    )
    return [value for value in options if value > 0]


def _autotune_cache_path() -> Path:
    return Path(__file__).resolve().parents[2] / ".dmark_cache" / "parse_tuning.json"


def _autotune_key() -> str:
    return "|".join(
        [
            str(os.cpu_count() or 0),
            platform.processor() or "unknown",
            platform.machine() or "unknown",
            f"{platform.python_implementation()}-{platform.python_version()}",
        ]
    )


def _get_tuned_workers() -> int | None:
    path = _autotune_cache_path()
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if payload.get("key") != _autotune_key():
        return None
    workers = payload.get("workers")
    if isinstance(workers, int) and workers > 0:
        return workers
    return None


def _save_tuned_workers(workers: int) -> None:
    path = _autotune_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "key": _autotune_key(),
        "workers": int(max(1, workers)),
        "updated_at_epoch": int(time.time()),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
