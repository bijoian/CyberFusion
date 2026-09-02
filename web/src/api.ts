import type { Asset, Collection, DashboardData, Finding, Health, Scan } from "./types";

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || "/api/v1").replace(/\/+$/, "");
const demoMode = import.meta.env.VITE_DEMO_MODE === "true";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: { Accept: "application/json" },
    signal,
  });

  if (!response.ok) {
    const message = (await response.text()).trim() || `Request failed with status ${response.status}`;
    throw new ApiError(message, response.status);
  }

  return (await response.json()) as T;
}

async function getCollection<T>(path: string, signal?: AbortSignal): Promise<Collection<T>> {
  const firstPage = await get<Collection<T>>(`${path}?limit=100`, signal);
  const offsets: number[] = [];
  for (let offset = firstPage.items.length; offset < firstPage.pagination.total; offset += firstPage.pagination.limit) {
    offsets.push(offset);
  }
  if (offsets.length === 0) {
    return firstPage;
  }

  const pages = await Promise.all(
    offsets.map((offset) => get<Collection<T>>(`${path}?limit=100&offset=${offset}`, signal)),
  );
  return {
    ...firstPage,
    items: [...firstPage.items, ...pages.flatMap((page) => page.items)],
  };
}

export async function getDashboardData(signal?: AbortSignal): Promise<DashboardData> {
  if (demoMode) {
    return demoDashboard;
  }

  const [health, scans, assets, findings] = await Promise.all([
    get<Health>("/health", signal),
    getCollection<Scan>("/scans", signal),
    getCollection<Asset>("/assets", signal),
    getCollection<Finding>("/findings", signal),
  ]);

  return { health, scans, assets, findings, demo: false };
}

const demoDashboard: DashboardData = {
  demo: true,
  health: { status: "demo" },
  scans: {
    pagination: { limit: 100, offset: 0, total: 3 },
    items: [
      {
        id: "demo-scan-003",
        name: "Perimeter inventory",
        description: "Authorized perimeter inventory",
        targets: ["192.0.2.0/24"],
        status: "completed",
        started_at: "2026-08-31T09:45:00Z",
        completed_at: "2026-08-31T09:49:21Z",
        duration_seconds: 261,
        risk_score: 72,
        created_at: "2026-08-31T09:45:00Z",
      },
      {
        id: "demo-scan-002",
        name: "DMZ follow-up",
        description: "Authorized infrastructure review",
        targets: ["198.51.100.18"],
        status: "completed",
        started_at: "2026-08-30T16:02:00Z",
        completed_at: "2026-08-30T16:04:15Z",
        duration_seconds: 135,
        risk_score: 46,
        created_at: "2026-08-30T16:02:00Z",
      },
      {
        id: "demo-scan-001",
        name: "Asset baseline",
        description: "Initial authorized asset inventory",
        targets: ["203.0.113.24"],
        status: "completed",
        started_at: "2026-08-27T11:20:00Z",
        completed_at: "2026-08-27T11:23:41Z",
        duration_seconds: 201,
        risk_score: 28,
        created_at: "2026-08-27T11:20:00Z",
      },
    ],
  },
  assets: {
    pagination: { limit: 100, offset: 0, total: 3 },
    items: [
      {
        id: "demo-asset-001",
        scan_id: "demo-scan-003",
        hostname: "edge-gateway",
        ip_address: "192.0.2.18",
        os: "Linux",
        os_version: "6.8",
        is_active: true,
        location: { latitude: 40.71, longitude: -74.01, country: "United States", city: "New York", region: "NY" },
        first_seen: "2026-08-27T11:22:00Z",
        last_seen: "2026-08-31T09:47:00Z",
      },
      {
        id: "demo-asset-002",
        scan_id: "demo-scan-003",
        hostname: "portal",
        ip_address: "192.0.2.28",
        os: "Linux",
        os_version: "6.8",
        is_active: true,
        location: { latitude: 51.51, longitude: -0.13, country: "United Kingdom", city: "London", region: "England" },
        first_seen: "2026-08-27T11:22:00Z",
        last_seen: "2026-08-31T09:47:00Z",
      },
      {
        id: "demo-asset-003",
        scan_id: "demo-scan-002",
        hostname: "api-dmz",
        ip_address: "198.51.100.18",
        os: "Linux",
        os_version: "5.15",
        is_active: true,
        location: { latitude: -23.55, longitude: -46.63, country: "Brazil", city: "Sao Paulo", region: "SP" },
        first_seen: "2026-08-30T16:03:00Z",
        last_seen: "2026-08-30T16:03:00Z",
      },
    ],
  },
  findings: {
    pagination: { limit: 100, offset: 0, total: 4 },
    items: [
      {
        id: "demo-finding-001",
        scan_id: "demo-scan-003",
        asset_id: "demo-asset-001",
        finding_type: "vulnerability",
        template_name: "TLS configuration",
        host: "192.0.2.18",
        protocol: "https",
        title: "Deprecated TLS protocol enabled",
        description: "The service accepts a protocol version that should be retired.",
        severity: "high",
        confidence: 94,
        status: "open",
        evidence: "Protocol negotiation identified a deprecated version.",
        remediation: "Disable deprecated TLS versions and verify the cipher policy.",
        sources: ["nmap"],
        references: [],
        first_seen: "2026-08-31T09:47:00Z",
        last_seen: "2026-08-31T09:47:00Z",
      },
      {
        id: "demo-finding-002",
        scan_id: "demo-scan-003",
        asset_id: "demo-asset-002",
        finding_type: "misconfiguration",
        template_name: "HTTP headers",
        host: "192.0.2.28",
        protocol: "https",
        title: "Missing security response headers",
        description: "Response hardening headers were not detected.",
        severity: "medium",
        confidence: 87,
        status: "open",
        evidence: "Strict-Transport-Security was absent from the response.",
        remediation: "Apply the recommended browser security headers at the edge.",
        sources: ["nuclei"],
        references: [],
        first_seen: "2026-08-31T09:48:00Z",
        last_seen: "2026-08-31T09:48:00Z",
      },
      {
        id: "demo-finding-003",
        scan_id: "demo-scan-002",
        asset_id: "demo-asset-003",
        finding_type: "vulnerability",
        template_name: "Service detection",
        host: "198.51.100.18",
        protocol: "tcp",
        title: "Outdated service version",
        description: "A detected service version requires review against vendor guidance.",
        severity: "critical",
        confidence: 98,
        status: "open",
        evidence: "Service fingerprint matched an affected version.",
        remediation: "Apply the vendor security update and rescan the authorized host.",
        sources: ["nmap"],
        references: ["CVE-2026-0001"],
        first_seen: "2026-08-30T16:03:00Z",
        last_seen: "2026-08-30T16:03:00Z",
      },
      {
        id: "demo-finding-004",
        scan_id: "demo-scan-001",
        asset_id: "demo-asset-001",
        finding_type: "information",
        template_name: "Service discovery",
        host: "192.0.2.18",
        protocol: "tcp",
        title: "Service inventory change",
        description: "A service was observed during the authorized inventory scan.",
        severity: "info",
        confidence: 100,
        status: "acknowledged",
        evidence: "Service discovery completed.",
        remediation: "No action required.",
        sources: ["nmap"],
        references: [],
        first_seen: "2026-08-27T11:22:00Z",
        last_seen: "2026-08-27T11:22:00Z",
      },
    ],
  },
};
