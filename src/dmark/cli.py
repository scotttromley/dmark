from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .parser import ParseError
from .pst_extract import (
    PstExtractError,
    extract_reports_from_pst,
    get_pst_backend_status,
    install_pstparse_dotnet_noninteractive,
)
from .reporting import analyze_inputs


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "extract-pst":
        return _run_extract_pst(args)
    if args.command == "analyze":
        return _run_analyze(args)
    if args.command == "serve":
        return _run_serve(args)
    if args.command == "setup-pst":
        return _run_setup_pst(args)

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dmark",
        description="Analyze DMARC aggregate report XML files and PST-derived attachments.",
    )
    subparsers = parser.add_subparsers(dest="command")

    extract_parser = subparsers.add_parser(
        "extract-pst",
        help="Extract DMARC XML attachments from a PST export.",
    )
    extract_parser.add_argument("pst_file", type=Path, help="Path to .pst file")
    extract_parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("extracted-reports"),
        help="Directory to write extracted report files",
    )
    extract_parser.add_argument(
        "--engine",
        choices=["auto", "pypff", "readpst", "pstparse-dotnet"],
        default="auto",
        help="Extraction backend to use",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze DMARC report XML/XML.GZ files from file(s) or directory(s).",
    )
    analyze_parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Input files/directories containing XML/XML.GZ DMARC reports",
    )
    analyze_parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write JSON summary",
    )
    analyze_parser.add_argument(
        "--min-fail-rate-alert",
        type=float,
        default=0.02,
        help="Failure-rate threshold for recommendations (default: 0.02)",
    )
    analyze_parser.add_argument(
        "--min-messages-alert",
        type=int,
        default=100,
        help="Minimum message count before fail-rate alerting (default: 100)",
    )
    analyze_parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Abort on first invalid file instead of skipping parse errors",
    )
    analyze_parser.add_argument(
        "--parse-workers",
        type=int,
        default=0,
        help="Parser worker threads (default: 0=auto)",
    )
    analyze_parser.add_argument(
        "--resolve-dns",
        action="store_true",
        help="Query DNS TXT/CNAME records to enrich remediation guidance.",
    )

    serve_parser = subparsers.add_parser(
        "serve",
        help="Run local web UI for report upload and analysis.",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Bind port (default: 8080)",
    )
    serve_parser.add_argument(
        "--max-upload-mb",
        type=int,
        default=1024,
        help="Max request size for uploads in MB (default: 1024)",
    )
    serve_parser.add_argument(
        "--min-fail-rate-alert",
        type=float,
        default=0.02,
        help="Default failure-rate threshold for recommendations",
    )
    serve_parser.add_argument(
        "--min-messages-alert",
        type=int,
        default=100,
        help="Default minimum message count before fail-rate alerting",
    )
    serve_parser.add_argument(
        "--parse-workers",
        type=int,
        default=0,
        help="Parser worker threads for web requests (default: 0=auto)",
    )
    serve_parser.add_argument(
        "--job-ttl-seconds",
        type=int,
        default=6 * 60 * 60,
        help=(
            "How long completed/failed PST jobs remain queryable in-memory "
            "(default: 21600)"
        ),
    )
    serve_parser.add_argument(
        "--max-jobs",
        type=int,
        default=500,
        help="Maximum PST jobs kept in-memory before oldest entries are pruned.",
    )

    setup_parser = subparsers.add_parser(
        "setup-pst",
        help="Check PST extraction backends and optionally install helper backends.",
    )
    setup_parser.add_argument(
        "--install-pstparse-dotnet",
        action="store_true",
        help="Build/install the bundled .NET PSTParse extraction helper.",
    )
    return parser


def _run_extract_pst(args: argparse.Namespace) -> int:
    try:
        files, engine = extract_reports_from_pst(
            pst_path=args.pst_file,
            out_dir=args.out_dir,
            engine=args.engine,
        )
    except PstExtractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Extraction engine: {engine}")
    print(f"Extracted files: {len(files)}")
    print(f"Output directory: {args.out_dir.resolve()}")
    return 0


def _run_analyze(args: argparse.Namespace) -> int:
    try:
        output = analyze_inputs(
            inputs=args.inputs,
            stop_on_error=args.stop_on_error,
            min_fail_rate_alert=args.min_fail_rate_alert,
            min_messages_alert=args.min_messages_alert,
            resolve_dns_records=args.resolve_dns,
            parse_workers=args.parse_workers,
        )
    except ParseError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    _print_human_summary(output)

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"\nWrote JSON report to {args.json_out.resolve()}")

    return 0


def _run_serve(args: argparse.Namespace) -> int:
    try:
        from .webapp import create_app
    except ImportError as exc:
        print(
            "ERROR: Web UI requires Flask. Install dependencies and retry.",
            file=sys.stderr,
        )
        print(f"Detail: {exc}", file=sys.stderr)
        return 2

    app = create_app(
        max_upload_mb=args.max_upload_mb,
        min_fail_rate_alert=args.min_fail_rate_alert,
        min_messages_alert=args.min_messages_alert,
        parse_workers=args.parse_workers,
        job_ttl_seconds=args.job_ttl_seconds,
        max_jobs=args.max_jobs,
    )
    print(f"Serving web UI at http://{args.host}:{args.port}")
    print("Use Ctrl+C to stop.")
    app.run(host=args.host, port=args.port)
    return 0


def _run_setup_pst(args: argparse.Namespace) -> int:
    did_action = False
    success = True

    if args.install_pstparse_dotnet:
        did_action = True
        ok, message = install_pstparse_dotnet_noninteractive()
        print(message)
        success = success and ok

    status = get_pst_backend_status()
    print(f"Backends: {status}")
    if did_action:
        return 0 if success else 2

    if not any(status.values()):
        print(
            "No PST extraction backends found. "
            "Run: dmark setup-pst --install-pstparse-dotnet"
        )
        return 2
    return 0


def _print_human_summary(output: dict[str, object]) -> None:
    print("DMARC Analysis Summary")
    print("======================")
    print(f"Files scanned: {output['files_scanned']}")
    print(f"Files parsed: {output['files_parsed']}")
    print(f"Parse errors: {output['parse_errors']}")
    print(f"Duplicate reports skipped: {output['duplicate_reports_skipped']}")

    domains = output["domains"]
    if not isinstance(domains, list):
        return

    for entry in domains:
        if not isinstance(entry, dict):
            continue
        print("")
        print(f"Domain: {entry.get('domain', 'unknown')}")
        print(f"  Reports: {entry.get('reports_seen', 0)}")
        print(f"  Messages: {entry.get('messages_total', 0)}")
        print(
            "  Protection posture: {} ({})".format(
                entry.get("protection_posture_grade", "-"),
                entry.get("protection_posture_score", 0),
            )
        )
        print(
            "  Historical trend score: {} ({})".format(
                entry.get("historical_trend_score", entry.get("health_score", 0)),
                entry.get("historical_trend_label", entry.get("health_label", "unknown")),
            )
        )
        trend_desc = entry.get("historical_trend_score_description")
        if trend_desc:
            print(f"    {trend_desc}")
        aggregate_evidence_note = entry.get("aggregate_evidence_note")
        if aggregate_evidence_note:
            print(f"    {aggregate_evidence_note}")
        print(
            "  Dual score (safety/posture): {}/{} (confidence: {})".format(
                entry.get("deliverability_safety_score", 0),
                entry.get("anti_spoofing_posture_score", 0),
                entry.get("score_confidence", "low"),
            )
        )
        print(
            "  Authentication coverage (legit): {:.2%} (DKIM {:.2%} / SPF {:.2%})".format(
                float(entry.get("authentication_coverage_rate", 0.0)),
                float(entry.get("authentication_coverage_dkim_rate", 0.0)),
                float(entry.get("authentication_coverage_spf_rate", 0.0)),
            )
        )
        print(
            "  Attack pressure: {} ({:.2%}, {} fails)".format(
                entry.get("attack_pressure_label", entry.get("attack_pressure_level", "Unknown")),
                float(entry.get("attack_pressure_fail_rate", 0.0)),
                int(entry.get("attack_pressure_fail_count", 0)),
            )
        )
        attack_note = entry.get("attack_pressure_note")
        if attack_note:
            print(f"    {attack_note}")
        safety_note = entry.get("deliverability_safety_note")
        if safety_note:
            print(f"  Deliverability note: {safety_note}")
        health_causes = entry.get("health_score_causes", [])
        if isinstance(health_causes, list) and health_causes:
            print("  Trend score drivers:")
            for cause in health_causes:
                print(f"    - {cause}")
        print(
            "  Policy/readiness: {} / {}".format(
                entry.get("dominant_policy", "unknown"),
                entry.get("enforcement_readiness", "unknown"),
            )
        )
        print(f"    Avg pct: {entry.get('average_policy_pct', 100)}")
        readiness_detail = entry.get("enforcement_readiness_detail")
        if readiness_detail:
            print(f"    {readiness_detail}")
        legitimate_basis = entry.get("legitimate_basis", {})
        if isinstance(legitimate_basis, dict):
            print(
                "    Readiness basis: {} (coverage {:.2%}, {} msgs, {} noise-excluded msgs)".format(
                    legitimate_basis.get("basis", "all_observed_traffic"),
                    float(legitimate_basis.get("coverage_rate", 0.0)),
                    legitimate_basis.get("messages_total", 0),
                    legitimate_basis.get("noise_messages_excluded", 0),
                )
            )
        dns_diagnostics = entry.get("dns_diagnostics", {})
        if isinstance(dns_diagnostics, dict) and dns_diagnostics.get("enabled"):
            print(
                "    DNS checks: DMARC {}, SPF {}, M365 DKIM {}".format(
                    "found" if dns_diagnostics.get("dmarc_record_found") else "missing",
                    "found" if dns_diagnostics.get("spf_record_found") else "missing",
                    dns_diagnostics.get("m365_dkim_status", "unknown"),
                )
            )
        print(
            "  DMARC pass/fail: {}/{} ({:.2%} pass)".format(
                entry.get("dmarc_pass_count", 0),
                entry.get("dmarc_fail_count", 0),
                float(entry.get("dmarc_pass_rate", 0.0)),
            )
        )
        print(
            "  DKIM auth/aligned pass rate: {:.2%} / {:.2%}".format(
                float(entry.get("dkim_auth_pass_rate", 0.0)),
                float(entry.get("dkim_aligned_pass_rate", 0.0)),
            )
        )
        print(
            "  SPF auth/aligned pass rate: {:.2%} / {:.2%}".format(
                float(entry.get("spf_auth_pass_rate", 0.0)),
                float(entry.get("spf_aligned_pass_rate", 0.0)),
            )
        )
        print(
            "  Alignment gap (DKIM/SPF): {:.2%} / {:.2%}".format(
                float(entry.get("dkim_alignment_gap_rate", 0.0)),
                float(entry.get("spf_alignment_gap_rate", 0.0)),
            )
        )
        print(f"  Dispositions: {entry.get('disposition_counts', {})}")
        impact = entry.get("policy_impact_simulation", {})
        if isinstance(impact, dict):
            quarantine = impact.get("quarantine_100", {})
            reject = impact.get("reject_100", {})
            if isinstance(quarantine, dict) and isinstance(reject, dict):
                print(f"  Policy impact basis: {impact.get('basis', 'all_observed_traffic')}")
                print("  Policy impact simulation:")
                print(
                    (
                        "    - quarantine pct=100: affects {} legitimate msgs ({:.2%}), "
                        "all-traffic {} msgs ({:.2%})"
                    ).format(
                        quarantine.get("estimated_legitimate_impacted_messages", 0),
                        float(quarantine.get("estimated_legitimate_impacted_rate", 0.0)),
                        quarantine.get("estimated_impacted_messages", 0),
                        float(quarantine.get("estimated_impacted_rate", 0.0)),
                    )
                )
                print(
                    (
                        "    - reject pct=100: affects {} legitimate msgs ({:.2%}), "
                        "all-traffic {} msgs ({:.2%})"
                    ).format(
                        reject.get("estimated_legitimate_impacted_messages", 0),
                        float(reject.get("estimated_legitimate_impacted_rate", 0.0)),
                        reject.get("estimated_impacted_messages", 0),
                        float(reject.get("estimated_impacted_rate", 0.0)),
                    )
                )
        sender_inventory_summary = entry.get("sender_inventory_summary", {})
        if isinstance(sender_inventory_summary, dict) and sender_inventory_summary:
            print(
                "  Sender inventory mix: approved {:.2%}, noise {:.2%}, pending {:.2%}".format(
                    float(sender_inventory_summary.get("approved_rate", 0.0)),
                    float(sender_inventory_summary.get("noise_rate", 0.0)),
                    float(sender_inventory_summary.get("pending_review_rate", 0.0)),
                )
            )
        sender_inventory = entry.get("sender_inventory", [])
        if isinstance(sender_inventory, list) and sender_inventory:
            print("  Top senders:")
            for sender in sender_inventory[:3]:
                if not isinstance(sender, dict):
                    continue
                approved = " approved" if sender.get("approved_sender") else ""
                new_label = " new" if sender.get("new_since_last_run") else ""
                share = float(sender.get("message_share_rate", 0.0))
                action_label = str(
                    sender.get("suggested_action_label", sender.get("suggested_action", "investigate"))
                ).replace("_", " ")
                print(
                    "    - {} ({} msgs, {:.2%} of domain, fail {:.2%}, action: {}){}{}".format(
                        sender.get("source_ip", "unknown"),
                        sender.get("message_count", 0),
                        share,
                        float(sender.get("dmarc_fail_rate", 0.0)),
                        action_label,
                        approved,
                        new_label,
                    )
                )
        top_sources = entry.get("top_failing_sources", [])
        if top_sources:
            first = top_sources[0]
            if isinstance(first, dict):
                source_class = first.get("classification", "unclassified")
                source_conf = first.get("classification_confidence", "low")
                source_tag = ""
                if source_class and source_class not in {"unclassified", "unknown"}:
                    source_tag = f" [{source_class}/{source_conf}]"
                print(
                    "  Top failing source: {} ({} messages){}".format(
                        first.get("source_ip", "unknown"),
                        first.get("message_count", 0),
                        source_tag,
                    )
                )
                investigation_conf = first.get("investigation_confidence")
                if investigation_conf:
                    print(f"    Investigation confidence: {investigation_conf}")
                investigation_note = first.get("investigation_note")
                if investigation_note:
                    print(f"    {investigation_note}")
                failure_mode = str(first.get("dkim_failure_mode", "unknown"))
                if failure_mode and failure_mode != "unknown":
                    print(f"    DKIM failure mode: {failure_mode}")
        relay_note = entry.get("receiver_side_security_relay_note")
        if relay_note:
            print(f"  Receiver-side relay note: {relay_note}")

        issues = entry.get("issues", [])
        if isinstance(issues, list) and issues:
            print("  Key issues:")
            for issue in issues[:4]:
                if not isinstance(issue, dict):
                    continue
                severity = issue.get("severity", "unknown")
                category = issue.get("category", "general")
                confidence = issue.get("confidence", "low")
                title = issue.get("title", "Issue")
                evidence = issue.get("evidence", "")
                cause = issue.get("likely_cause", "")
                print(f"    - [{severity}/{category}/{confidence}] {title}")
                if evidence:
                    print(f"      Evidence: {evidence}")
                if cause:
                    print(f"      Likely cause: {cause}")

        action_plan = entry.get("action_plan", [])
        if isinstance(action_plan, list) and action_plan:
            print("  Suggested actions:")
            for idx, step in enumerate(action_plan[:6], start=1):
                print(f"    {idx}. {step}")

        recommendations = entry.get("recommendations", [])
        if recommendations:
            print("  Recommendation summary:")
            for item in recommendations[:3]:
                print(f"    - {item}")


if __name__ == "__main__":
    raise SystemExit(main())
