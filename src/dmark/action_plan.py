"""Dynamic DMARC action plan generation."""

from __future__ import annotations


def _build_dynamic_action_plan(
    domain: str,
    dominant_policy: str,
    sender_inventory: list[dict[str, object]],
    default_action_plan: list[str],
    dns_diagnostics: dict[str, object] | None = None,
    m365_alignment_sender: dict[str, object] | None = None,
    dkim_aligned_rate: float = 0.0,
    spf_alignment_gap_rate: float = 0.0,
    legitimate_fail_rate: float = 0.0,
    m365_is_heavy: bool = False,
    m365_failing_messages: int = 0,
    m365_dkim_carrying_load: bool = False,
    legitimate_dkim_failure_modes: dict[str, int] | None = None,
    legitimate_forwarding_related_count: int = 0,
) -> list[str]:
    dns_diagnostics = dns_diagnostics or {}
    m365_present = any(
        isinstance(sender, dict)
        and sender.get("classification") == "esp_microsoft365_outbound"
        for sender in sender_inventory
    )
    legitimate_dkim_failure_modes = legitimate_dkim_failure_modes or {}
    if not m365_is_heavy and m365_present and m365_failing_messages <= 0:
        # Fallback for callers that don't precompute these values.
        m365_failing_messages = sum(
            int(sender.get("dmarc_fail_count", 0))
            for sender in sender_inventory
            if isinstance(sender, dict)
            and sender.get("classification") == "esp_microsoft365_outbound"
        )
    m365_safe_banner = bool(m365_is_heavy and m365_dkim_carrying_load)
    m365_spf_gap_expected = bool(
        m365_present
        and dns_diagnostics.get("m365_dkim_status") == "configured"
        and dkim_aligned_rate >= 0.90
        and spf_alignment_gap_rate >= 0.05
    )
    filtered_default_plan = (
        _filter_m365_spf_low_value_steps(default_action_plan)
        if m365_spf_gap_expected
        else list(default_action_plan)
    )
    selected_sender = m365_alignment_sender
    if selected_sender is None:
        for sender in sender_inventory:
            if not isinstance(sender, dict):
                continue
            if sender.get("classification") != "esp_microsoft365_outbound":
                continue
            if sender.get("suggested_action") != "fix_alignment":
                continue
            if int(sender.get("dmarc_fail_count", 0)) <= 0:
                continue
            selected_sender = sender
            break

    if selected_sender is None:
        if not m365_spf_gap_expected:
            return filtered_default_plan
        if m365_safe_banner:
            celebratory_plan = [
                "Authentication status: excellent (p=reject appears safe).",
                (
                    "Microsoft 365 sender paths account for "
                    f"{m365_failing_messages} failing messages in this window."
                ),
                "DKIM status: Microsoft 365 DKIM is configured, authenticated, and valid.",
                (
                    "SPF alignment lag is normal Microsoft 365 envelope-from behavior "
                    "(protection.outlook.com/onmicrosoft.com)."
                ),
                (
                    "DMARC uses aligned SPF OR aligned DKIM. Current DKIM alignment "
                    f"({dkim_aligned_rate:.2%}) is carrying legitimate authentication."
                ),
                "No action required on the SPF gap at this time.",
                (
                    "Do not add receiver relay/scanner hosts (for example cloud-sec-av.com) "
                    "to SPF unless they are confirmed sender paths."
                ),
                "Optional: continue monitoring for 30 days, then consider BIMI readiness.",
            ]
            return _merge_unique_steps(
                celebratory_plan,
                _append_legitimate_dkim_triage_steps(
                    filtered_default_plan,
                    legitimate_dkim_failure_modes,
                    legitimate_forwarding_related_count,
                ),
            )
        reassuring_plan = [
            "DKIM status: Microsoft 365 DKIM is configured and selector records are present.",
            (
                "SPF alignment gap is a common Microsoft 365 envelope-from behavior "
                "(onmicrosoft.com/protection.outlook.com return paths)."
            ),
            (
                "DMARC uses aligned SPF OR aligned DKIM; strong DKIM alignment is currently carrying "
                "authentication for most legitimate traffic."
            ),
        ]
        if legitimate_fail_rate <= 0.02:
            reassuring_plan.append(
                (
                    "No urgent SPF realignment is required while legitimate DMARC fail rate stays low "
                    f"({legitimate_fail_rate:.2%})."
                )
            )
        else:
            reassuring_plan.append(
                (
                    f"Legitimate DMARC fail rate is {legitimate_fail_rate:.2%}; investigate remaining "
                    "failing sender paths before changing SPF policy."
                )
            )
        return _merge_unique_steps(
            reassuring_plan,
            _append_legitimate_dkim_triage_steps(
                filtered_default_plan,
                legitimate_dkim_failure_modes,
                legitimate_forwarding_related_count,
            ),
        )

    routing_domain = (domain or "").replace(".", "-")
    selector_checks = dns_diagnostics.get("dkim_selector_checks", {})
    selector1_status = None
    selector2_status = None
    if isinstance(selector_checks, dict):
        selector1_status = selector_checks.get("selector1")
        selector2_status = selector_checks.get("selector2")
    selector1_cname = (
        selector1_status.get("cname")
        if isinstance(selector1_status, dict)
        else None
    )
    selector2_cname = (
        selector2_status.get("cname")
        if isinstance(selector2_status, dict)
        else None
    )
    m365_dkim_ready = bool(
        selector1_cname and selector2_cname
    )
    dynamic_plan: list[str] = []
    if dominant_policy == "reject" and not m365_spf_gap_expected:
        dynamic_plan.append(
            "CRITICAL: Domain is enforcing p=reject. Fix Microsoft 365 alignment promptly to reduce delivery risk."
        )

    if m365_safe_banner:
        dynamic_plan.extend(
            [
                "Authentication status: excellent (p=reject appears safe).",
                (
                    "Microsoft 365 sender paths account for "
                    f"{m365_failing_messages} failing messages in this window."
                ),
                "DKIM status: Microsoft 365 DKIM is configured, authenticated, and valid.",
                (
                    "SPF alignment lag is normal Microsoft 365 envelope-from behavior "
                    "(protection.outlook.com/onmicrosoft.com)."
                ),
                (
                    "DMARC uses aligned SPF OR aligned DKIM. Current DKIM alignment "
                    f"({dkim_aligned_rate:.2%}) is carrying legitimate authentication."
                ),
                "No action required on the SPF gap at this time.",
                (
                    "Do not add receiver relay/scanner hosts (for example cloud-sec-av.com) "
                    "to SPF unless they are confirmed sender paths."
                ),
                "Optional: continue monitoring for 30 days, then consider BIMI readiness.",
            ]
        )
        if m365_dkim_ready:
            if selector1_cname:
                dynamic_plan.append(f"Observed selector1 CNAME: {selector1_cname}")
            if selector2_cname:
                dynamic_plan.append(f"Observed selector2 CNAME: {selector2_cname}")
    elif m365_spf_gap_expected:
        dynamic_plan.extend(
            [
                (
                    "Microsoft 365 sender paths account for "
                    f"{int(selected_sender.get('dmarc_fail_count_total_m365', selected_sender.get('dmarc_fail_count', 0)))} "
                    "failing messages in this window."
                ),
                "DKIM status: Microsoft 365 DKIM is configured and authenticated.",
                (
                    "SPF alignment lag is commonly caused by Microsoft 365 envelope-from routing and "
                    "does not automatically indicate DMARC enforcement risk."
                ),
                (
                    "DMARC uses aligned SPF OR aligned DKIM. Current aligned DKIM coverage is "
                    f"{dkim_aligned_rate:.2%}."
                ),
                (
                    "Do not add third-party receiver relay/scanner hosts to SPF unless they are "
                    "confirmed sender paths."
                ),
            ]
        )
        if legitimate_fail_rate <= 0.02:
            dynamic_plan.append(
                (
                    "No urgent SPF realignment is required while legitimate DMARC fail rate remains "
                    f"{legitimate_fail_rate:.2%}."
                )
            )
        else:
            dynamic_plan.append(
                (
                    f"Legitimate DMARC fail rate is {legitimate_fail_rate:.2%}; review remaining failing "
                    "flows, then decide whether SPF path changes are needed."
                )
            )
        if m365_dkim_ready:
            dynamic_plan.append(
                (
                    "DNS check confirms selector1/selector2 DKIM CNAME records are present; verify DKIM "
                    "is enabled in the M365 portal if alignment unexpectedly drops."
                )
            )
            if selector1_cname:
                dynamic_plan.append(f"Observed selector1 CNAME: {selector1_cname}")
            if selector2_cname:
                dynamic_plan.append(f"Observed selector2 CNAME: {selector2_cname}")
    elif m365_dkim_ready:
        dynamic_plan.extend(
            [
                (
                    "Microsoft 365 alignment gap detected on outbound protection sender "
                    f"{selected_sender.get('source_ip', 'unknown')} "
                    f"({int(selected_sender.get('dmarc_fail_count_total_m365', selected_sender.get('dmarc_fail_count', 0)))} failing messages across detected M365 sender paths)."
                ),
                (
                    "Preferred fix: enable DKIM for the domain in Microsoft 365 Defender "
                    "(Email & collaboration -> Policies & rules -> Threat policies -> DKIM)."
                ),
                (
                    "DNS check: selector1/selector2 DKIM CNAME records are already present; "
                    "if DKIM alignment is still low, verify DKIM is enabled in the M365 portal."
                ),
                f"Observed selector1 CNAME: {selector1_cname}",
                f"Observed selector2 CNAME: {selector2_cname}",
                "After DNS propagation, enable DKIM in Microsoft 365 and re-run this report in 24-48 hours.",
                "Do not add third-party receiver relay/scanner hosts to SPF unless they are confirmed sender paths.",
            ]
        )
    else:
        dynamic_plan.extend(
            [
                (
                    "Microsoft 365 alignment gap detected on outbound protection sender "
                    f"{selected_sender.get('source_ip', 'unknown')} "
                    f"({int(selected_sender.get('dmarc_fail_count_total_m365', selected_sender.get('dmarc_fail_count', 0)))} failing messages across detected M365 sender paths)."
                ),
                (
                    "Preferred fix: enable DKIM for the domain in Microsoft 365 Defender "
                    "(Email & collaboration -> Policies & rules -> Threat policies -> DKIM)."
                ),
                (
                    "Publish selector1 CNAME: selector1._domainkey -> "
                    f"selector1-{routing_domain}._domainkey.<your-tenant>.onmicrosoft.com"
                ),
                (
                    "Publish selector2 CNAME: selector2._domainkey -> "
                    f"selector2-{routing_domain}._domainkey.<your-tenant>.onmicrosoft.com"
                ),
                "After DNS propagation, enable DKIM in Microsoft 365 and re-run this report in 24-48 hours.",
                "Do not add third-party receiver relay/scanner hosts to SPF unless they are confirmed sender paths.",
            ]
        )

    # Preserve one generic step as a fallback reminder for any non-M365 senders.
    if filtered_default_plan:
        dynamic_plan.append(
            "If non-M365 senders still fail, fix alignment on those specific sender platforms."
        )
    merged = _merge_unique_steps(dynamic_plan, filtered_default_plan)
    return _append_legitimate_dkim_triage_steps(
        merged,
        legitimate_dkim_failure_modes,
        legitimate_forwarding_related_count,
    )


def _filter_m365_spf_low_value_steps(steps: list[str]) -> list[str]:
    blocked_patterns = (
        "custom mail from",
        "return-path",
        "publish spf records on those envelope domains",
        "flatten",
    )
    filtered: list[str] = []
    for step in steps:
        normalized = str(step).strip()
        if not normalized:
            continue
        lower = normalized.lower()
        if any(pattern in lower for pattern in blocked_patterns):
            continue
        filtered.append(normalized)
    return filtered


def _merge_unique_steps(primary: list[str], fallback: list[str]) -> list[str]:
    merged: list[str] = []
    for step in list(primary) + list(fallback):
        normalized = str(step).strip()
        if not normalized:
            continue
        if normalized in merged:
            continue
        merged.append(normalized)
    return merged


def _append_legitimate_dkim_triage_steps(
    steps: list[str],
    legitimate_dkim_failure_modes: dict[str, int],
    legitimate_forwarding_related_count: int,
) -> list[str]:
    triage_steps: list[str] = []
    missing = int(legitimate_dkim_failure_modes.get("dkim_missing", 0))
    auth_fail = int(legitimate_dkim_failure_modes.get("dkim_auth_fail", 0))
    unaligned = int(legitimate_dkim_failure_modes.get("dkim_pass_unaligned", 0))
    if missing > 0:
        triage_steps.append(
            f"DKIM triage: {missing} legitimate failing messages had no DKIM signature. Ensure that sender workflow signs with DKIM."
        )
    if auth_fail > 0:
        triage_steps.append(
            f"DKIM triage: {auth_fail} legitimate failing messages had DKIM authentication failures; investigate relays or content rewrites breaking signatures."
        )
    if unaligned > 0:
        triage_steps.append(
            f"DKIM triage: {unaligned} legitimate failing messages had DKIM pass but unaligned d= domains; configure aligned signing domains/selectors."
        )
    if legitimate_forwarding_related_count > 0:
        triage_steps.append(
            f"Indirect-flow signal: {legitimate_forwarding_related_count} legitimate messages show forwarding/mailing-list/local-policy overrides. Treat SPF failures cautiously and validate DKIM before concluding misconfiguration."
        )
    return _merge_unique_steps(steps, triage_steps)
