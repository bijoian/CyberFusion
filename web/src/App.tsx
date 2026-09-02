import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { ApiError, getDashboardData } from "./api";
import type { Asset, DashboardData, Finding, Scan, Severity } from "./types";

const severities = ["critical", "high", "medium", "low", "info"] as const;
type SeverityName = (typeof severities)[number];

function App() {
  const [data, setData] = useState<DashboardData>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<string>();
  const [stale, setStale] = useState(false);
  const [filter, setFilter] = useState({ severity: "all", status: "all" });
  const [selectedFinding, setSelectedFinding] = useState<Finding>();

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(undefined);
    try {
      const result = await getDashboardData(signal);
      if (!signal?.aborted) {
        setData(result);
        setLastUpdated(new Date().toISOString());
        setStale(false);
      }
    } catch (requestError) {
      if (!signal?.aborted) {
        const message = requestError instanceof ApiError ? requestError.message : "Unable to reach the Control API.";
        setError(message);
        setStale(true);
      }
    } finally {
      if (!signal?.aborted) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const visibleFindings = useMemo(() => {
    if (!data) return [];
    return data.findings.items.filter((finding) => {
      const severityMatches = filter.severity === "all" || finding.severity.toLowerCase() === filter.severity;
      const statusMatches = filter.status === "all" || finding.status.toLowerCase() === filter.status;
      return severityMatches && statusMatches;
    });
  }, [data, filter]);

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#overview" aria-label="CyberFusion Control home">
          <span className="brand-mark" aria-hidden="true">C</span>
          <span>CyberFusion <strong>Control</strong></span>
        </a>
        <nav aria-label="Primary navigation">
          <a href="#overview">Overview</a>
          <a href="#scans">Scans</a>
          <a href="#assets">Assets</a>
          <a href="#findings">Findings</a>
          <a href="#risk-map">Risk map</a>
        </nav>
        <button className="refresh" type="button" onClick={() => void load()} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh data"}
        </button>
      </header>

      {data?.demo && <div className="demo-banner" role="status">Demo mode: labeled fixture data is being shown. No Control API data is in use.</div>}
      <TabletStatus data={data} loading={loading} stale={stale} lastUpdated={lastUpdated} />

      {loading && !data && <LoadingState />}
      {error && !data && <ErrorState message={error} onRetry={() => void load()} />}
      {data && (
        <>
          {error && <div className="stale-banner" role="alert">Control API unavailable. Displaying data last confirmed {formatDateTime(lastUpdated)}.</div>}
          <section className="hero" id="overview" aria-labelledby="overview-title">
            <div>
              <p className="eyebrow">Security intelligence</p>
              <h1 id="overview-title">Know where exposure is building.</h1>
              <p className="hero-copy">A read-only Control view of authorized scan results, asset exposure, and remediation priorities.</p>
            </div>
            <HealthStatus status={data.health.status} demo={data.demo} stale={stale} />
          </section>
          <Overview data={data} />
          <Scans scans={data.scans.items} assets={data.assets.items} total={data.scans.pagination.total} />
          <Assets assets={data.assets.items} total={data.assets.pagination.total} />
          <Findings
            findings={visibleFindings}
            total={data.findings.pagination.total}
            filter={filter}
            onFilter={setFilter}
            onSelect={setSelectedFinding}
          />
          <RiskMap assets={data.assets.items} findings={data.findings.items} />
        </>
      )}
      {selectedFinding && <FindingDetail finding={selectedFinding} onClose={() => setSelectedFinding(undefined)} />}
    </main>
  );
}

function TabletStatus({ data, loading, stale, lastUpdated }: {
  data?: DashboardData;
  loading: boolean;
  stale: boolean;
  lastUpdated?: string;
}) {
  const counts = data ? countSeverities(data.findings.items) : undefined;
  const scannerActive = data?.scans.items.some((scan) => scan.status === "running" || scan.status === "pending");
  const apiLabel = loading ? "Checking" : stale || !data || data.health.status !== "ok" ? "Inactive" : "Active";
  const scannerLabel = stale || !data ? "Unavailable" : scannerActive ? "Active" : "Inactive";

  return (
    <section className="tablet-status" aria-label="Live Control status">
      <div className="tablet-status-heading">
        <div><p className="eyebrow">Live status</p><strong>{stale ? "Data may be stale" : data?.demo ? "Demo data" : "Control summary"}</strong></div>
        <small>{lastUpdated && !loading ? `Confirmed ${formatDateTime(lastUpdated)}` : loading ? "Contacting API" : "No live data available"}</small>
      </div>
      <div className="status-pills">
        <span className={`status-pill ${apiLabel.toLowerCase()}`}><i aria-hidden="true" />API {apiLabel}</span>
        <span className={`status-pill ${scannerLabel.toLowerCase()}`}><i aria-hidden="true" />Scanner {scannerLabel}</span>
      </div>
      <div className="tablet-severity-grid" aria-label="Vulnerability totals by severity">
        {severities.map((severity) => <div className={severity} key={severity}><small>{capitalize(severity)}</small><strong>{counts ? counts[severity] : "--"}</strong></div>)}
      </div>
    </section>
  );
}

function Overview({ data }: { data: DashboardData }) {
  const severityCounts = countSeverities(data.findings.items);
  const vulnerableAssets = new Set(data.findings.items.filter((finding) => finding.asset_id).map((finding) => finding.asset_id)).size;
  const riskScore = Math.max(0, ...data.scans.items.map((scan) => scan.risk_score));
  return (
    <section className="section overview" aria-label="Risk overview">
      <div className="risk-panel">
        <p className="eyebrow">Current risk posture</p>
        <div className="risk-score">
          <strong>{riskScore}</strong><span>/100</span>
        </div>
        <p>{riskCopy(riskScore)} Review critical and high findings first.</p>
        <div className="risk-scale" aria-label={`Risk score ${riskScore} out of 100`}><i style={{ width: `${Math.min(riskScore, 100)}%` }} /></div>
      </div>
      <div className="metric-grid">
        <Metric label="Assets" value={data.assets.pagination.total} hint={`${vulnerableAssets} with findings`} tone="blue" />
        <Metric label="Open findings" value={data.findings.items.filter((finding) => finding.status === "open").length} hint={`${data.findings.pagination.total} collected`} tone="violet" />
        {severities.slice(0, 2).map((severity) => <Metric key={severity} label={severity} value={severityCounts[severity]} hint="Findings requiring review" tone={severity} />)}
      </div>
      <div className="severity-panel">
        <div className="section-heading"><div><p className="eyebrow">Severity distribution</p><h2>Exposure by severity</h2></div></div>
        <div className="severity-bars">
          {severities.map((severity) => <SeverityBar key={severity} severity={severity} count={severityCounts[severity]} total={data.findings.items.length} />)}
        </div>
      </div>
    </section>
  );
}

function Scans({ scans, assets, total }: { scans: Scan[]; assets: Asset[]; total: number }) {
  return (
    <section className="section" id="scans" aria-labelledby="scans-title">
      <SectionTitle eyebrow="Authorized activity" title="Recent scans" count={total} id="scans-title" />
      {scans.length === 0 ? <EmptyState title="No scans yet" text="Completed scans will appear here when the Control API has results." /> : (
        <div className="scan-grid">
          {scans.slice(0, 6).map((scan) => <ScanCard key={scan.id} scan={scan} assets={assets.filter((asset) => asset.scan_id === scan.id)} />)}
        </div>
      )}
    </section>
  );
}

function ScanCard({ scan, assets }: { scan: Scan; assets: Asset[] }) {
  const hostnames = uniqueValues(assets.map((asset) => asset.hostname));
  const addresses = uniqueValues([...assets.map((asset) => asset.ip_address), ...scan.targets]);
  const targetLabel = hostnames.join(", ") || scan.targets.join(", ") || "Not recorded";
  const networkAddress = addresses.join(", ") || "Not recorded";

  return <article className="scan-card">
    <div className="scan-card-top"><Status value={scan.status} /><time dateTime={scan.created_at}>{formatDate(scan.created_at)}</time></div>
    <h3>{scan.name || "Untitled scan"}</h3>
    <p>{scan.description || `${scan.targets.length} authorized target${scan.targets.length === 1 ? "" : "s"}`}</p>
    <dl className="scan-targets">
      <div><dt>Target label</dt><dd>{targetLabel}</dd></div>
      <div><dt>Network address</dt><dd className="mono">{networkAddress}</dd></div>
    </dl>
    <div className="scan-meta"><span>{assets.length ? `${assets.length} discovered asset${assets.length === 1 ? "" : "s"}` : "No discovered assets"}</span><strong>Risk {scan.risk_score}/100</strong></div>
  </article>;
}

function Assets({ assets, total }: { assets: Asset[]; total: number }) {
  return (
    <section className="section" id="assets" aria-labelledby="assets-title">
      <SectionTitle eyebrow="Inventory" title="Assets" count={total} id="assets-title" />
      {assets.length === 0 ? <EmptyState title="No assets discovered" text="Assets appear after an authorized scan records results." /> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th scope="col">Asset</th><th scope="col">Address</th><th scope="col">Platform</th><th scope="col">Location</th><th scope="col">Observed</th><th scope="col">State</th></tr></thead>
            <tbody>{assets.map((asset) => <tr key={asset.id}>
              <td><strong>{asset.hostname || "Unnamed asset"}</strong></td>
              <td className="mono">{asset.ip_address || "Not recorded"}</td>
              <td>{[asset.os, asset.os_version].filter(Boolean).join(" ") || "Unknown"}</td>
              <td>{locationName(asset)}</td>
              <td>{formatDate(asset.last_seen)}</td>
              <td><Status value={asset.is_active ? "active" : "inactive"} /></td>
            </tr>)}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Findings({ findings, total, filter, onFilter, onSelect }: {
  findings: Finding[];
  total: number;
  filter: { severity: string; status: string };
  onFilter: (filter: { severity: string; status: string }) => void;
  onSelect: (finding: Finding) => void;
}) {
  return (
    <section className="section" id="findings" aria-labelledby="findings-title">
      <div className="section-heading findings-heading">
        <div><p className="eyebrow">Triage queue</p><h2 id="findings-title">Findings <span>{total}</span></h2></div>
        <div className="filters" aria-label="Filter findings">
          <label>Severity<select value={filter.severity} onChange={(event) => onFilter({ ...filter, severity: event.target.value })}><option value="all">All severities</option>{severities.map((severity) => <option key={severity} value={severity}>{capitalize(severity)}</option>)}</select></label>
          <label>Status<select value={filter.status} onChange={(event) => onFilter({ ...filter, status: event.target.value })}><option value="all">All statuses</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="remediated">Remediated</option><option value="false_positive">False positive</option></select></label>
        </div>
      </div>
      {findings.length === 0 ? <EmptyState title="No matching findings" text="Adjust the filters or run an authorized scan to populate this queue." /> : (
        <div className="finding-list">{findings.map((finding) => <button className="finding-row" type="button" key={finding.id} onClick={() => onSelect(finding)}>
          <span className={`severity-dot ${finding.severity.toLowerCase()}`} aria-hidden="true" />
          <span className="finding-main"><strong>{finding.title || "Untitled finding"}</strong><small>{finding.host || finding.asset?.hostname || "Asset not recorded"} · {finding.finding_type || "Finding"}</small></span>
          <span><SeverityBadge severity={finding.severity} /><small>{capitalize(finding.status || "unknown")}</small></span>
          <span className="row-chevron" aria-hidden="true">›</span>
        </button>)}</div>
      )}
    </section>
  );
}

function RiskMap({ assets, findings }: { assets: Asset[]; findings: Finding[] }) {
  const mappedAssets = assets.filter(hasCoordinates);
  return (
    <section className="section risk-map-section" id="risk-map" aria-labelledby="map-title">
      <SectionTitle eyebrow="Geographic exposure" title="Risk map" count={mappedAssets.length} id="map-title" />
      {mappedAssets.length === 0 ? <EmptyState title="No geographic data" text="The API has not recorded latitude and longitude for any assets. The accessible asset inventory remains available above." /> : (
        <div className="map-layout">
          <div className="map-card">
            <div className="world-map" role="img" aria-label={`${mappedAssets.length} assets with geographic coordinates`}>
              <svg viewBox="0 0 1000 480" preserveAspectRatio="none" aria-hidden="true"><path d="M60 120l105-64 95 42 55 83-38 68-86-5-58-48-66-1zm264 6l95-36 79 51 34 105-50 58-73-31-58-69zm210-89l120 39 58 84-36 65-106-13-43-73zm188 137l129-25 84 71-35 104-104 3-68-68zM356 300l90-43 57 80-45 108-67-42zm188-8l82-24 77 59-31 108-93-8-51-70z" /></svg>
              {mappedAssets.map((asset) => <span className={`map-marker ${assetRisk(asset, findings)}`} key={asset.id} style={markerPosition(asset)} title={`${asset.hostname || asset.ip_address}: ${locationName(asset)}`} />)}
            </div>
            <p className="map-caption">Markers reflect API-provided asset coordinates. Marker color indicates the highest related finding severity.</p>
          </div>
          <div className="location-list" aria-label="Geographic risk list">
            {mappedAssets.map((asset) => <div className="location-item" key={asset.id}><span className={`severity-dot ${assetRisk(asset, findings)}`} aria-hidden="true" /><div><strong>{asset.hostname || asset.ip_address || "Unnamed asset"}</strong><small>{locationName(asset)}</small></div><SeverityBadge severity={assetRisk(asset, findings)} /></div>)}
          </div>
        </div>
      )}
    </section>
  );
}

function FindingDetail({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const drawerRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeButtonRef.current?.focus();
    return () => previousFocus.current?.focus();
  }, []);

  function handleKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key === "Escape") {
      onClose();
      return;
    }
    if (event.key !== "Tab" || !drawerRef.current) return;

    const focusable = Array.from(
      drawerRef.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    );
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!drawerRef.current.contains(document.activeElement) || (!event.shiftKey && document.activeElement === last)) {
      event.preventDefault();
      first.focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    }
  }

  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={onClose}>
      <aside ref={drawerRef} className="drawer" role="dialog" aria-modal="true" aria-labelledby="detail-title" onKeyDown={handleKeyDown} onMouseDown={(event) => event.stopPropagation()}>
        <button ref={closeButtonRef} className="close-button" type="button" onClick={onClose} aria-label="Close finding details">×</button>
        <p className="eyebrow">Finding detail</p>
        <div className="detail-title"><SeverityBadge severity={finding.severity} /><h2 id="detail-title">{finding.title || "Untitled finding"}</h2></div>
        <dl className="detail-meta"><div><dt>Status</dt><dd>{capitalize(finding.status || "unknown")}</dd></div><div><dt>Confidence</dt><dd>{finding.confidence}%</dd></div><div><dt>Host</dt><dd className="mono">{finding.host || finding.asset?.ip_address || "Not recorded"}</dd></div><div><dt>Source</dt><dd>{finding.sources.filter(Boolean).join(", ") || "Not recorded"}</dd></div></dl>
        <DetailSection title="Description" value={finding.description} />
        <DetailSection title="Evidence" value={finding.evidence} />
        <DetailSection title="Recommended remediation" value={finding.remediation} highlighted />
        {finding.references.filter(Boolean).length > 0 && <DetailSection title="References" value={finding.references.join(", ")} />}
      </aside>
    </div>
  );
}

function DetailSection({ title, value, highlighted = false }: { title: string; value: string; highlighted?: boolean }) {
  if (!value) return null;
  return <section className={highlighted ? "detail-section remediation" : "detail-section"}><h3>{title}</h3><p>{value}</p></section>;
}

function LoadingState() {
  return <section className="state-card loading-state" aria-live="polite"><span className="spinner" aria-hidden="true" /><div><h1>Loading Control data</h1><p>Contacting the versioned CyberFusion API.</p></div></section>;
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <section className="state-card error-state" role="alert"><p className="eyebrow">Control API unavailable</p><h1>Data could not be loaded.</h1><p>{message}</p><button className="primary-button" type="button" onClick={onRetry}>Try again</button></section>;
}

function EmptyState({ title, text }: { title: string; text: string }) {
  return <div className="empty-state"><strong>{title}</strong><p>{text}</p></div>;
}

function HealthStatus({ status, demo, stale }: { status: string; demo: boolean; stale: boolean }) {
  const healthy = (status === "ok" || demo) && !stale;
  return <div className={`health ${healthy ? "healthy" : "unhealthy"}`}><span aria-hidden="true" /><div><small>Control API</small><strong>{stale ? "Data stale" : demo ? "Demo data" : status === "ok" ? "Operational" : "Degraded"}</strong></div></div>;
}

function SectionTitle({ eyebrow, title, count, id }: { eyebrow: string; title: string; count: number; id?: string }) {
  return <div className="section-heading"><div><p className="eyebrow">{eyebrow}</p><h2 id={id}>{title} <span>{count}</span></h2></div></div>;
}

function Metric({ label, value, hint, tone }: { label: string; value: number; hint: string; tone: string }) {
  return <article className={`metric ${tone}`}><p>{label}</p><strong>{value}</strong><small>{hint}</small></article>;
}

function SeverityBar({ severity, count, total }: { severity: SeverityName; count: number; total: number }) {
  const width = total ? Math.max((count / total) * 100, count ? 4 : 0) : 0;
  return <div className="severity-bar"><span><i className={`severity-dot ${severity}`} />{capitalize(severity)}</span><div><i className={severity} style={{ width: `${width}%` }} /></div><strong>{count}</strong></div>;
}

function Status({ value }: { value: string }) {
  return <span className={`status ${value.toLowerCase().replace(/_/g, "-")}`}>{capitalize(value || "unknown")}</span>;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const normalized = severity.toLowerCase();
  return <span className={`severity-badge ${normalized}`}>{capitalize(normalized || "unknown")}</span>;
}

function countSeverities(findings: Finding[]): Record<SeverityName, number> {
  return severities.reduce((counts, severity) => {
    counts[severity] = findings.filter((finding) => finding.severity.toLowerCase() === severity).length;
    return counts;
  }, {} as Record<SeverityName, number>);
}

function assetRisk(asset: Asset, findings: Finding[]): string {
  const related = findings.filter((finding) => finding.asset_id === asset.id).map((finding) => finding.severity.toLowerCase());
  return severities.find((severity) => related.includes(severity)) || "info";
}

function hasCoordinates(asset: Asset): boolean {
  return Number.isFinite(asset.location?.latitude) && Number.isFinite(asset.location?.longitude) &&
    asset.location.latitude >= -90 && asset.location.latitude <= 90 && asset.location.longitude >= -180 && asset.location.longitude <= 180;
}

function markerPosition(asset: Asset): { left: string; top: string } {
  return { left: `${((asset.location.longitude + 180) / 360) * 100}%`, top: `${((90 - asset.location.latitude) / 180) * 100}%` };
}

function locationName(asset: Asset): string {
  return [asset.location?.city, asset.location?.country].filter(Boolean).join(", ") || "Not recorded";
}

function uniqueValues(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function formatDate(value: string | null): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not recorded" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

function formatDateTime(value?: string): string {
  if (!value) return "at an unknown time";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "at an unknown time" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function riskCopy(score: number): string {
  if (score >= 75) return "Critical exposure is present.";
  if (score >= 50) return "Elevated exposure needs attention.";
  if (score >= 25) return "Moderate exposure is being tracked.";
  return "Exposure is currently low.";
}

function capitalize(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

export default App;
