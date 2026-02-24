const statusEl = document.getElementById("status");
const explainWrapEl = document.getElementById("explainWrap");
const metricsEl = document.getElementById("metrics");
const summaryWrapEl = document.getElementById("summaryWrap");
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

function fmtInt(value) {
    return Number(value || 0).toLocaleString();
}

function esc(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function basisLabel(value) {
    const raw = String(value || "all_observed_traffic");
    if (raw === "approved_and_auto_approved_non_noise_senders") {
        return "approved sender traffic (excluding relay noise)";
    }
    if (raw === "all_observed_traffic_excluding_noise") {
        return "all observed traffic (excluding relay noise)";
    }
    return raw.replace(/_/g, " ");
}

function legitimateRiskNarrative(domain, policy) {
    const legitimateBasis = domain.legitimate_basis || {};
    const failRate = Number(legitimateBasis.fail_rate || 0);
    const failCount = Number(legitimateBasis.fail_count || 0);
    const total = Number(legitimateBasis.messages_total || 0);
    const spfGap = Number(domain.spf_alignment_gap_rate || 0);
    const dkimGap = Number(domain.dkim_alignment_gap_rate || 0);

    let how = "review top failing approved senders and fix whichever aligned path (DKIM or SPF) is failing.";
    if (spfGap >= 0.05 && Number(domain.dkim_aligned_pass_rate || 0) >= 0.9) {
        how = "reduce SPF alignment gaps on legitimate senders (for example custom/ aligned return-path domains), while keeping DKIM as primary.";
    } else if (dkimGap >= 0.02) {
        how = "fix DKIM alignment/signature survival first, then re-check SPF alignment.";
    }

    if (policy === "reject" && failRate <= 0.01) {
        return (
            "Reject policy is active and legitimate mail impact appears low. "
            + `Why: only ${fmtPct(failRate)} legitimate failures were observed (${fmtInt(failCount)} of ${fmtInt(total)}). `
            + "How: keep current posture, monitor trend drift, and remediate any new approved-sender failures quickly."
        );
    }

    if (policy === "reject") {
        return (
            "Reject policy is active, but legitimate mail impact is above ideal and should be reduced. "
            + `Why: ${fmtPct(failRate)} legitimate failures were observed (${fmtInt(failCount)} of ${fmtInt(total)}). `
            + `How: ${how}`
        );
    }

    if (policy === "quarantine") {
        return (
            "Quarantine policy is active; reject-level enforcement is not fully in place yet. "
            + `Why: legitimate fail rate is ${fmtPct(failRate)} on the current readiness basis. `
            + "How: stabilize aligned authentication and then stage toward reject."
        );
    }

    if (policy === "none") {
        return (
            "Monitor-only mode is active; spoofed messages are not fully blocked by policy. "
            + `Why: published policy is p=none while fail rates are ${fmtPct(Number(domain.dmarc_fail_rate || 0))}. `
            + "How: fix failing legitimate sender alignment first, then stage to quarantine/reject."
        );
    }

    return (
        "Policy posture is mixed or unclear; verify published DMARC policy consistency. "
        + "Why: reports show multiple policy states in this window. "
        + "How: validate DNS policy history and analyze a narrower date range if needed."
    );
}

function attackPressureNarrative(domain) {
    const attackPressureRate = Number(domain.attack_pressure_fail_rate || 0);
    const attackPressureCount = Number(domain.attack_pressure_fail_count || 0);
    if (attackPressureRate >= 0.02) {
        return (
            "Attack pressure is elevated, which usually reflects blocked unauthorized sender traffic. "
            + `Why: ${fmtPct(attackPressureRate)} (${fmtInt(attackPressureCount)} messages) failed outside approved sender traffic. `
            + "How: keep enforcement active and investigate only the highest-volume unknown non-noise sources."
        );
    }
    if (attackPressureRate > 0) {
        return (
            "Attack pressure is present but currently limited. "
            + `Why: ${fmtPct(attackPressureRate)} (${fmtInt(attackPressureCount)} messages) failed outside approved sender traffic. `
            + "How: continue monitoring and prioritize remediation on legitimate sender alignment."
        );
    }
    return "";
}

function relayNoiseNarrative(domain) {
    const relayFailCount = Number(domain.receiver_side_security_relay_fail_count || 0);
    if (relayFailCount <= 0) {
        return "";
    }
    return (
        "Receiver-side security relay traffic is present; treat it as analysis noise unless confirmed as your sender path. "
        + `Why: ${fmtInt(relayFailCount)} failures were classified as receiver-side relay patterns. `
        + "How: do not add those relay IPs to SPF; focus remediation on approved sender infrastructure."
    );
}

function domainReadabilityStatus(domain) {
    const policy = String(domain.dominant_policy || "unknown").toLowerCase();
    const readiness = String(domain.enforcement_readiness || "").toLowerCase();
    const legitimateBasis = domain.legitimate_basis || {};
    const legitimateFailRate = Number(legitimateBasis.fail_rate || 0);

    if (readiness.includes("not_ready") || legitimateFailRate >= 0.03) {
        return { label: "Action needed", css: "risk-high" };
    }
    if (policy === "none" || legitimateFailRate >= 0.01) {
        return { label: "Watch closely", css: "risk-medium" };
    }
    return { label: "Stable", css: "risk-low" };
}

function domainInterpretation(domain) {
    const policy = String(domain.dominant_policy || "unknown").toLowerCase();
    const lines = [];

    lines.push(legitimateRiskNarrative(domain, policy));
    const attackLine = attackPressureNarrative(domain);
    if (attackLine) lines.push(attackLine);
    const noiseLine = relayNoiseNarrative(domain);
    if (noiseLine) lines.push(noiseLine);

    return lines;
}

function renderExplanation(data, domains) {
    const filesScanned = Number(data.files_scanned || 0);
    const filesParsed = Number(data.files_parsed || 0);
    const parseErrors = Number(data.parse_errors || 0);
    const duplicates = Number(data.duplicate_reports_skipped || 0);
    const domainCount = Array.isArray(domains) ? domains.length : 0;

    const qualityNotes = [];
    if (parseErrors === 0) {
        qualityNotes.push("No parse errors were detected, so report coverage is complete for recognized input files.");
    } else {
        qualityNotes.push(`${fmtInt(parseErrors)} files failed to parse. Review parse errors before making final policy decisions.`);
    }
    if (duplicates > 0) {
        qualityNotes.push(`${fmtInt(duplicates)} duplicate aggregate reports were skipped to prevent double-counting.`);
    } else {
        qualityNotes.push("No duplicate reports were detected.");
    }

    explainWrapEl.innerHTML = `
    <article class="first-run-guide">
      <h3>How To Read This Result</h3>
      <div class="guide-topline">
        <span><strong>${fmtInt(filesParsed)}</strong> of <strong>${fmtInt(filesScanned)}</strong> files parsed</span>
        <span><strong>${fmtInt(domainCount)}</strong> domain${domainCount === 1 ? "" : "s"} analyzed</span>
      </div>
      <div class="guide-notes">${qualityNotes.map((note) => `<div>${esc(note)}</div>`).join("")}</div>
      <details>
        <summary>Plain-language glossary</summary>
        <div class="guide-glossary">
          <div><strong>Deliverability safety:</strong> risk of hurting legitimate mail if enforcement is tightened.</div>
          <div><strong>Attack pressure:</strong> unauthorized or unapproved sender failures, separated from legitimate sender risk.</div>
          <div><strong>Authentication coverage:</strong> percent of legitimate traffic with aligned DKIM or SPF.</div>
          <div><strong>SPF alignment gap:</strong> SPF passes authentication, but Return-Path domain is not aligned to visible From domain.</div>
          <div><strong>Receiver-side noise:</strong> relay/scanning infrastructure (for example cloud-sec-av.com) that can inflate fail counts.</div>
          <div><strong>Readiness basis:</strong> traffic slice used for safety decisions, typically approved sender traffic minus noise.</div>
        </div>
      </details>
    </article>
  `;
}

function renderDomainSummaryCards(domains) {
    if (!Array.isArray(domains) || !domains.length) {
        summaryWrapEl.innerHTML = "";
        return;
    }

    const cards = domains.map((d) => {
        const status = domainReadabilityStatus(d);
        const interpretations = domainInterpretation(d);
        const legitimateBasis = d.legitimate_basis || {};
        const senderSummary = d.sender_inventory_summary || {};
        const topActions = (Array.isArray(d.action_plan) ? d.action_plan : []).slice(0, 3);
        const topIssues = (Array.isArray(d.issues) ? d.issues : []).slice(0, 3);
        const topSources = (Array.isArray(d.top_failing_sources) ? d.top_failing_sources : []).slice(0, 3);
        const policy = `${d.dominant_policy || "unknown"} (${(Number(d.policy_consistency || 0) * 100).toFixed(0)}%, pct ${Number(d.average_policy_pct || 100).toFixed(0)})`;

        const issueHtml = topIssues.length
            ? topIssues.map((issue) => `<div class="mini"><strong>${esc(issue.severity || "low")}:</strong> ${esc(issue.title || "Issue")}</div>`).join("")
            : "<div class='mini'>No key issues flagged.</div>";

        const sourceHtml = topSources.length
            ? topSources.map((source) => {
                const host = source.hostname ? ` -> ${esc(source.hostname)}` : "";
                return `<div class="mini mono">${esc(source.source_ip)} (${fmtInt(source.message_count || 0)})${host}</div>`;
            }).join("")
            : "<div class='mini'>No concentrated failing sources.</div>";

        const actionHtml = topActions.length
            ? `<ol class="action-list">${topActions.map((step) => `<li>${esc(step)}</li>`).join("")}</ol>`
            : "<div class='mini'>No action steps were generated.</div>";

        return `
      <article class="domain-brief ${status.css}">
        <header>
          <h3>${esc(d.domain || "unknown")}</h3>
          <span class="risk-pill ${status.css}">${esc(status.label)}</span>
        </header>
        <div class="brief-grid">
          <div><strong>Policy:</strong> ${esc(policy)}</div>
          <div><strong>Readiness:</strong> ${esc(d.enforcement_readiness || "-")}</div>
          <div><strong>Legitimate fail rate:</strong> ${fmtPct(legitimateBasis.fail_rate)}</div>
          <div><strong>Attack pressure:</strong> ${fmtPct(d.attack_pressure_fail_rate)} (${fmtInt(d.attack_pressure_fail_count || 0)} fails)</div>
          <div><strong>Auth coverage:</strong> ${fmtPct(d.authentication_coverage_rate)} (DKIM ${fmtPct(d.authentication_coverage_dkim_rate)} / SPF ${fmtPct(d.authentication_coverage_spf_rate)})</div>
          <div><strong>Readiness basis:</strong> ${esc(basisLabel(legitimateBasis.basis))}</div>
        </div>
        <div class="what-means">
          <strong>What this means:</strong>
          ${interpretations.map((line) => `<div class="mini">${esc(line)}</div>`).join("")}
        </div>
        <div class="action-now">
          <strong>What to do now:</strong>
          ${actionHtml}
        </div>
        <details>
          <summary>See evidence and advanced diagnostics</summary>
          <div class="advanced-grid">
            <div>
              <strong>Top issues</strong>
              ${issueHtml}
            </div>
            <div>
              <strong>Top failing sources</strong>
              ${sourceHtml}
            </div>
            <div>
              <strong>Sender mix context</strong>
              <div class="mini">Approved: ${fmtPct(senderSummary.approved_rate)} (${fmtInt(senderSummary.approved_messages || 0)} msgs)</div>
              <div class="mini">Noise excluded: ${fmtPct(senderSummary.noise_rate)} (${fmtInt(senderSummary.noise_messages || 0)} msgs)</div>
              <div class="mini">Pending review: ${fmtPct(senderSummary.pending_review_rate)} (${fmtInt(senderSummary.pending_review_messages || 0)} msgs)</div>
            </div>
          </div>
        </details>
      </article>
    `;
    }).join("");

    summaryWrapEl.innerHTML = `
    <div class="summary-head">
      <h2>First-Pass Interpretation</h2>
      <p>Start here for action-oriented decisions. Use the detailed table below for full diagnostics.</p>
    </div>
    <div class="domain-brief-grid">${cards}</div>
  `;
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
    renderExplanation(data, domains);
    renderDomainSummaryCards(domains);
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
    explainWrapEl.innerHTML = "";
    metricsEl.innerHTML = "";
    summaryWrapEl.innerHTML = "";
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
