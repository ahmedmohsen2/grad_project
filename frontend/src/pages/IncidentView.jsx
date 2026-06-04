import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import Panel from "../components/common/Panel";
import ProgressBar from "../components/common/ProgressBar";
import StatusBadge from "../components/common/StatusBadge";
import { formatTimestamp } from "../utils/formatters";
import {
  getAlerts,
  getPentestFindings,
  getPentestResults,
  listPentestScans,
  scanStatusBadgeClass,
  severityBadgeClass,
} from "../api/api";
import { socApi } from "../services/socApi";

function buildHeaderTone(status) {
  if (status === "active" || status === "unresolved") {
    return "border-red-500/40 bg-red-500/10";
  }
  if (status === "mitigated") {
    return "border-emerald-500/40 bg-emerald-500/10";
  }
  return "border-orange-500/40 bg-orange-500/10";
}

function toneForStatus(status) {
  if (status === "active" || status === "unresolved") return "danger";
  if (status === "mitigated") return "success";
  return "warning";
}

function resolveStatus({ finding, scanDetails, latestAction, detections }) {
  if (scanDetails?.status === "running") return "active";
  if (finding?.mitigation_state === "mitigated") return "mitigated";
  if (finding?.mitigation_state === "unresolved" || finding?.status === "still_vulnerable") return "unresolved";
  if (latestAction?.action_type === "BLOCK" || latestAction?.action_type === "ISOLATE") return "ongoing";
  if ((detections || []).some((item) => item.result === "ATTACK")) return "active";
  return "ongoing";
}

function resolveIdentifierContext(identifier, alerts, scans, findings) {
  const cleanIdentifier = decodeURIComponent(String(identifier || "").trim());
  if (!cleanIdentifier) {
    return { identifier: "", target: "", alert: null, scan: null, finding: null };
  }

  const alertMatch = alerts.find((item) => String(item.id) === cleanIdentifier);
  const scanMatch = scans.find((item) => item.scan_id === cleanIdentifier);
  const findingMatch =
    findings.find((item) => item.finding_id === cleanIdentifier) ||
    findings.find((item) => item.target === cleanIdentifier);

  const target =
    scanMatch?.target ||
    alertMatch?.ip ||
    findingMatch?.target ||
    cleanIdentifier;

  const scan =
    scanMatch ||
    scans
      .filter((item) => item.target === target)
      .sort((left, right) => String(right.created_at).localeCompare(String(left.created_at)))[0] ||
    null;

  const finding =
    findingMatch ||
    findings
      .filter((item) => item.target === target)
      .sort((left, right) => String(right.updated_at).localeCompare(String(left.updated_at)))[0] ||
    null;

  return {
    identifier: cleanIdentifier,
    target,
    alert: alertMatch || null,
    scan,
    finding,
  };
}

function deriveEventReportKey(event, vulnerabilities, findings) {
  const metadata = event.metadata || {};
  if (metadata.finding_id) return metadata.finding_id;

  const findingMatch = findings.find(
    (item) =>
      item.finding_id === metadata.finding_id ||
      (item.title && event.reason && event.reason.toLowerCase().includes(String(item.title).toLowerCase())),
  );
  if (findingMatch) return findingMatch.finding_id;

  const vulnMatch = vulnerabilities.find(
    (item) =>
      item.vuln_id === metadata.finding_id ||
      (item.title && event.reason && event.reason.toLowerCase().includes(String(item.title).toLowerCase())),
  );
  return vulnMatch?.vuln_id || null;
}

export default function IncidentView({ soc }) {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [query, setQuery] = useState(decodeURIComponent(id || ""));
  const [alerts, setAlerts] = useState([]);
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scanDetails, setScanDetails] = useState(null);
  const [activityLogs, setActivityLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTimelineKey, setActiveTimelineKey] = useState(null);
  const [activeReportKey, setActiveReportKey] = useState(null);
  const timelineRefs = useRef({});
  const reportRefs = useRef({});

  useEffect(() => {
    setQuery(decodeURIComponent(id || ""));
  }, [id]);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      try {
        const [alertRows, scanRows, findingRows] = await Promise.all([
          getAlerts(120),
          listPentestScans(120),
          getPentestFindings(120, null, true),
        ]);
        if (cancelled) return;
        setAlerts(alertRows);
        setScans(scanRows);
        setFindings(findingRows);

        const context = resolveIdentifierContext(id, alertRows, scanRows, findingRows);
        const requests = [];
        if (context.scan?.scan_id) {
          requests.push(getPentestResults(context.scan.scan_id));
        } else {
          requests.push(Promise.resolve(null));
        }
        if (context.target) {
          requests.push(socApi.getActivityLogs({ target: context.target, limit: 120 }).catch(() => []));
        } else {
          requests.push(Promise.resolve([]));
        }

        const [scanRecord, logRows] = await Promise.all(requests);
        if (cancelled) return;
        setScanDetails(scanRecord);
        setActivityLogs(Array.isArray(logRows) ? logRows : []);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, [id]);

  const context = useMemo(
    () => resolveIdentifierContext(id, alerts, scans, findings),
    [alerts, findings, id, scans],
  );

  const relatedFindings = useMemo(
    () =>
      findings
        .filter((item) => item.target === context.target)
        .sort((left, right) => String(right.updated_at).localeCompare(String(left.updated_at))),
    [context.target, findings],
  );

  const latestFinding = relatedFindings[0] || context.finding || null;
  const latestAction = useMemo(
    () =>
      [...(soc.actions || [])]
        .filter((item) => item.ip === context.target)
        .sort((left, right) => String(right.acted_at).localeCompare(String(left.acted_at)))[0] || null,
    [context.target, soc.actions],
  );

  const targetDetections = useMemo(
    () => (soc.detections || []).filter((item) => item.src_ip === context.target),
    [context.target, soc.detections],
  );

  const status = resolveStatus({
    finding: latestFinding,
    scanDetails,
    latestAction,
    detections: targetDetections,
  });

  const report = scanDetails?.results?.report || null;
  const vulnerabilities = useMemo(() => {
    const scanVulns = scanDetails?.results?.vulnerabilities || [];
    if (scanVulns.length > 0) return scanVulns;
    return relatedFindings.map((item) => ({
      vuln_id: item.finding_id,
      title: item.title,
      description: item.description,
      severity: String(item.severity || "medium").toLowerCase(),
      confidence: item.confidence,
      remediation: item.remediation,
      affected_component: item.affected_component,
      evidence: item.evidence,
      classification: item.classification || item.metadata?.classification,
      validation_status: item.validation_status || item.metadata?.validation_status,
      evidence_source: item.evidence_source || item.metadata?.evidence_source,
      related_port: item.related_port || item.metadata?.related_port,
      protocol: item.protocol || item.metadata?.protocol,
      detection_method: item.detection_method || item.metadata?.detection_method,
    }));
  }, [relatedFindings, scanDetails]);

  const recommendations = useMemo(() => {
    const reportRecommendations = report?.recommendations || [];
    if (reportRecommendations.length > 0) return reportRecommendations;
    return [...new Set(relatedFindings.map((item) => item.remediation).filter(Boolean))];
  }, [relatedFindings, report]);

  const timelineEvents = useMemo(
    () =>
      [...activityLogs]
        .sort((left, right) => String(left.created_at || left.timestamp).localeCompare(String(right.created_at || right.timestamp)))
        .map((event, index) => ({
          ...event,
          timelineKey: String(event.id || `${event.action}-${index}`),
        })),
    [activityLogs],
  );

  const executionSummary = scanDetails?.results?.execution_plan || {};
  const currentAction =
    executionSummary.steps?.[executionSummary.current_step || 0]?.action ||
    latestAction?.action_type ||
    "Monitoring";

  const riskScore = latestFinding?.risk_score ?? report?.risk_score ?? 0;

  const goToIncident = () => {
    if (!query.trim()) return;
    navigate(`/incident/${encodeURIComponent(query.trim())}`);
  };

  const highlightReportFromTimeline = (event) => {
    const reportKey = deriveEventReportKey(event, vulnerabilities, relatedFindings);
    if (!reportKey) return;
    setActiveTimelineKey(event.timelineKey);
    setActiveReportKey(reportKey);
    reportRefs.current[reportKey]?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const highlightTimelineFromVulnerability = (vulnerability) => {
    const reportKey = vulnerability.vuln_id || vulnerability.finding_id || vulnerability.title;
    const eventMatch = timelineEvents.find((event) => {
      const metadata = event.metadata || {};
      return (
        metadata.finding_id === reportKey ||
        (event.reason && vulnerability.title && event.reason.toLowerCase().includes(String(vulnerability.title).toLowerCase()))
      );
    });
    setActiveReportKey(reportKey);
    if (!eventMatch) return;
    setActiveTimelineKey(eventMatch.timelineKey);
    timelineRefs.current[eventMatch.timelineKey]?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  return (
    <div className="space-y-6">
      <Panel title="Unified Incident View" subtitle="Incident">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end">
          <div className="flex-1">
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500">
              Incident Selector
            </label>
            <input
              type="text"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => event.key === "Enter" && goToIncident()}
              placeholder="Enter IP, scan ID, or alert ID"
              className="w-full rounded-xl border border-slate-700 bg-slate-900/60 px-4 py-3 text-sm text-white outline-none focus:border-sky-500/60 focus:ring-1 focus:ring-sky-500/30"
            />
          </div>
          <button
            type="button"
            onClick={goToIncident}
            className="rounded-xl bg-sky-500/15 px-5 py-3 text-sm font-semibold text-sky-300 ring-1 ring-sky-500/30 transition hover:bg-sky-500/25"
          >
            Load Incident
          </button>
        </div>
      </Panel>

      <section className={`rounded-2xl border p-5 shadow-[0_14px_34px_rgba(2,6,23,0.35)] ${buildHeaderTone(status)}`}>
        <div className="grid gap-4 lg:grid-cols-[1.25fr_0.75fr_0.7fr_0.7fr]">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-slate-300/70">Target</p>
            <h2 className="mt-2 break-all text-3xl font-semibold text-white">{context.target || "--"}</h2>
            <p className="mt-2 text-sm text-slate-200/80">
              One place to follow the incident from detection through response and re-test.
            </p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-slate-300/70">Status</p>
            <div className="mt-3">
              <StatusBadge label={status} tone={toneForStatus(status)} />
            </div>
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-slate-300/70">Risk Score</p>
            <div className="mt-2 text-4xl font-bold text-white">{riskScore}</div>
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-slate-300/70">Last Action</p>
            <div className="mt-2 text-sm font-medium text-white">{latestAction?.action_type || "Pending"}</div>
            <div className="mt-1 text-xs text-slate-200/75">{latestAction?.source || "manual"}</div>
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.9fr_0.8fr_0.9fr]">
        <Panel title="Lifecycle Story" subtitle="Timeline">
          {loading ? (
            <div className="py-10 text-sm text-slate-400">Loading timeline...</div>
          ) : timelineEvents.length === 0 ? (
            <div className="py-10 text-sm text-slate-500">No timeline events found for this incident.</div>
          ) : (
            <div className="max-h-[74vh] space-y-3 overflow-y-auto pr-2">
              {timelineEvents.map((event) => (
                <button
                  key={event.timelineKey}
                  type="button"
                  ref={(node) => {
                    if (node) timelineRefs.current[event.timelineKey] = node;
                  }}
                  onClick={() => highlightReportFromTimeline(event)}
                  className={`w-full rounded-xl border p-4 text-left transition ${
                    activeTimelineKey === event.timelineKey
                      ? "border-sky-500/50 bg-sky-500/10"
                      : "border-slate-800/60 bg-slate-900/40 hover:border-slate-700"
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-sm font-medium text-white">
                      {(event.action || "event").replaceAll("_", " ")}
                    </div>
                    <StatusBadge
                      label={event.status || event.type || "event"}
                      tone={
                        event.status === "resolved"
                          ? "success"
                          : event.status === "failed"
                            ? "danger"
                            : event.type === "alert"
                              ? "warning"
                              : "info"
                      }
                    />
                  </div>
                  <p className="mt-2 text-sm text-slate-300">{event.reason || "No narrative available."}</p>
                  <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-500">
                    <span>{formatTimestamp(event.timestamp || event.created_at)}</span>
                    {event.source ? <span>source: {event.source}</span> : null}
                    {event.metadata?.scan_id ? <span>scan: {event.metadata.scan_id}</span> : null}
                  </div>
                </button>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Live Execution" subtitle="Execution Panel">
          <div className="space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-xs uppercase tracking-wider text-slate-500">Scan</div>
                <div className="mt-1 font-mono text-sm text-sky-300">{context.scan?.scan_id || "--"}</div>
              </div>
              <span className={`inline-flex rounded-full px-3 py-1 text-xs font-medium ${scanStatusBadgeClass(scanDetails?.status || context.scan?.status || "queued")}`}>
                {scanDetails?.status || context.scan?.status || "queued"}
              </span>
            </div>

            {scanDetails?.status === "running" ? (
              <>
                <div className="rounded-xl border border-orange-500/30 bg-orange-500/10 p-4 text-sm text-orange-200">
                  Live stage: {(scanDetails.current_stage || "queued").replaceAll("_", " ")}
                </div>
                <ProgressBar
                  label="Scan Progress"
                  value={Number(scanDetails.progress || 0)}
                  toneClass="bg-gradient-to-r from-orange-500 to-amber-500"
                />
              </>
            ) : (
              <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500">Execution Summary</div>
                <p className="mt-3 whitespace-pre-wrap text-sm leading-relaxed text-slate-300">
                  {report?.executive_summary || "No final execution summary is available yet."}
                </p>
              </div>
            )}

            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500">Current Action</div>
                <div className="mt-2 text-sm font-medium text-white">{currentAction}</div>
              </div>
              <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
                <div className="text-xs uppercase tracking-wider text-slate-500">Last Update</div>
                <div className="mt-2 text-sm font-medium text-white">
                  {formatTimestamp(scanDetails?.updated_at || context.scan?.updated_at || latestFinding?.updated_at)}
                </div>
              </div>
            </div>

            {executionSummary.steps?.length > 0 ? (
              <div className="space-y-2">
                {executionSummary.steps.slice(0, 5).map((step, index) => (
                  <div
                    key={`${step.action}-${index}`}
                    className={`rounded-lg border px-3 py-3 text-sm ${
                      index === (executionSummary.current_step || 0) && !executionSummary.is_complete
                        ? "border-sky-500/40 bg-sky-500/10 text-sky-200"
                        : "border-slate-800/60 bg-slate-900/40 text-slate-300"
                    }`}
                  >
                    <div className="font-medium text-white">{step.action}</div>
                    <div className="mt-1 text-xs text-slate-400">{step.reason}</div>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </Panel>

        <Panel title="Pentest Report" subtitle="Report Panel">
          <div className="space-y-5">
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
              <div className="text-xs uppercase tracking-wider text-slate-500">Risk</div>
              <div className="mt-3 flex items-center gap-3">
                <div className="text-5xl font-bold text-white">{riskScore}</div>
                <div className={`rounded-full px-3 py-1 text-xs font-medium ${severityBadgeClass(report?.risk_level || latestFinding?.severity || "medium")}`}>
                  {String(report?.risk_level || latestFinding?.severity || "medium").toUpperCase()}
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <div className="text-xs uppercase tracking-wider text-slate-500">Vulnerabilities</div>
              {vulnerabilities.length === 0 ? (
                <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 text-sm text-slate-500">
                  No vulnerabilities are attached to this incident.
                </div>
              ) : (
                vulnerabilities.map((item, index) => {
                  const reportKey = item.vuln_id || item.finding_id || item.title || `vuln-${index}`;
                  return (
                    <button
                      key={reportKey}
                      type="button"
                      ref={(node) => {
                        if (node) reportRefs.current[reportKey] = node;
                      }}
                      onClick={() => highlightTimelineFromVulnerability(item)}
                      className={`w-full rounded-xl border p-4 text-left transition ${
                        activeReportKey === reportKey
                          ? "border-sky-500/50 bg-sky-500/10"
                          : "border-slate-800/60 bg-slate-900/40 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="text-sm font-medium text-white">{item.title}</div>
                          <div className="mt-1 text-xs text-slate-400">
                            {item.affected_component || "General finding"}
                          </div>
                        </div>
                        <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${severityBadgeClass(item.severity)}`}>
                          {String(item.severity).toUpperCase()}
                        </span>
                      </div>
                      <p className="mt-3 text-sm text-slate-300">{item.description || "No description available."}</p>
                      <div className="mt-3 grid gap-2 text-[11px] text-slate-500 sm:grid-cols-2">
                        <span>classification: {item.classification || "SUSPECTED"}</span>
                        <span>validation: {item.validation_status || "requires review"}</span>
                        <span>source: {item.evidence_source || "scan"}</span>
                        <span>service: {item.related_port ? `${item.protocol || "tcp"}/${item.related_port}` : item.affected_component || "-"}</span>
                      </div>
                      {item.detection_method ? <p className="mt-2 text-[11px] text-sky-300/80">Detection method: {item.detection_method}</p> : null}
                      {item.evidence ? <p className="mt-2 rounded-lg border border-slate-800 bg-slate-950/40 p-2 font-mono text-[11px] text-slate-300">{item.evidence}</p> : null}
                      {item.classification === "HEURISTIC" ? (
                        <div className="mt-2 rounded-lg border border-amber-500/20 bg-amber-500/10 p-2 text-[11px] text-amber-200">
                          Analyst validation required before confirmation.
                        </div>
                      ) : null}
                    </button>
                  );
                })
              )}
            </div>

            <div className="space-y-3">
              <div className="text-xs uppercase tracking-wider text-slate-500">Recommendations</div>
              {recommendations.length === 0 ? (
                <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 text-sm text-slate-500">
                  No recommendations were generated for this incident.
                </div>
              ) : (
                recommendations.map((item, index) => (
                  <div key={`${item}-${index}`} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 text-sm text-slate-300">
                    {item}
                  </div>
                ))
              )}
            </div>
          </div>
        </Panel>
      </section>
    </div>
  );
}
