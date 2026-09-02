export type Severity = "critical" | "high" | "medium" | "low" | "info" | string;

export interface Pagination {
  limit: number;
  offset: number;
  total: number;
}

export interface Collection<T> {
  items: T[];
  pagination: Pagination;
}

export interface Health {
  status: string;
}

export interface GeoLocation {
  latitude: number;
  longitude: number;
  country: string;
  city: string;
  region: string;
}

export interface Scan {
  id: string;
  name: string;
  description: string;
  targets: string[];
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number;
  risk_score: number;
  created_at: string;
}

export interface Asset {
  id: string;
  scan_id: string;
  hostname: string;
  ip_address: string;
  os: string;
  os_version: string;
  location: GeoLocation;
  is_active: boolean;
  first_seen: string;
  last_seen: string;
  findings?: Finding[];
}

export interface Vulnerability {
  id: string;
  cve: string;
  cwe: string;
  cves: string[];
  cwes: string[];
  title: string;
  description: string;
  cvss: number;
  cvss_vector: string;
  severity: Severity;
}

export interface Finding {
  id: string;
  scan_id: string;
  asset_id: string;
  finding_type: string;
  template_name: string;
  host: string;
  protocol: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  status: string;
  evidence: string;
  remediation: string;
  sources: string[];
  references: string[];
  first_seen: string;
  last_seen: string;
  asset?: Asset;
  vulnerability?: Vulnerability;
}

export interface DashboardData {
  health: Health;
  scans: Collection<Scan>;
  assets: Collection<Asset>;
  findings: Collection<Finding>;
  demo: boolean;
}
