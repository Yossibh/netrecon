import { z } from 'zod';

export const InputTypeSchema = z.enum(['domain', 'ip', 'url']);
export type InputType = z.infer<typeof InputTypeSchema>;

export const NormalizedInputSchema = z.object({
  raw: z.string(),
  type: InputTypeSchema,
  domain: z.string().optional(),
  host: z.string().optional(),
  ip: z.string().optional(),
  ipVersion: z.enum(['v4', 'v6']).optional(),
  url: z.string().url().optional(),
});
export type NormalizedInput = z.infer<typeof NormalizedInputSchema>;

export const SeveritySchema = z.enum(['info', 'low', 'medium', 'high']);
export type Severity = z.infer<typeof SeveritySchema>;

export const FindingSchema = z.object({
  id: z.string(),
  severity: SeveritySchema,
  title: z.string(),
  explanation: z.string(),
  evidence: z.array(z.string()).default([]),
  nextSteps: z.array(z.string()).default([]),
  suggestedCommands: z.array(z.string()).default([]),
  module: z.string().optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

export interface DnsRecord {
  name: string;
  type: string;
  ttl?: number;
  data: string;
}

export interface DnsModuleResult {
  ok: boolean;
  error?: string;
  records: {
    A: DnsRecord[];
    AAAA: DnsRecord[];
    CNAME: DnsRecord[];
    MX: DnsRecord[];
    TXT: DnsRecord[];
    NS: DnsRecord[];
    CAA: DnsRecord[];
    SOA: DnsRecord[];
  };
  hasIPv6: boolean;
  hasCAA: boolean;
  dnssec?: boolean;
}

export interface HttpRedirect {
  from: string;
  to: string;
  status: number;
}

export interface HttpModuleResult {
  ok: boolean;
  error?: string;
  skipped?: boolean;
  skipReason?: string;
  finalUrl?: string;
  status?: number;
  redirects: HttpRedirect[];
  headers: Record<string, string>;
  securityHeaders: {
    hsts?: string;
    csp?: string;
    xContentTypeOptions?: string;
    xFrameOptions?: string;
    referrerPolicy?: string;
    permissionsPolicy?: string;
  };
  corsHeaders: {
    accessControlAllowOrigin?: string;
    accessControlAllowCredentials?: string;
  };
  cacheHeaders: {
    cacheControl?: string;
    age?: string;
    etag?: string;
    expires?: string;
  };
  server?: string;
  timingMs?: number;
  /** Live TLS session metadata from the Cloudflare fetch subrequest (when available). */
  liveTls?: { version?: string; cipher?: string };
}

export interface EmailModuleResult {
  ok: boolean;
  error?: string;
  skipped?: boolean;
  skipReason?: string;
  spf?: { present: boolean; raw?: string; qualifier?: string };
  dmarc?: { present: boolean; raw?: string; policy?: 'none' | 'quarantine' | 'reject' };
  mtaSts?: { present: boolean; raw?: string };
  bimi?: { present: boolean; raw?: string };
  mxPresent: boolean;
  dkimSelectorProbe?: { selector: string; present: boolean; raw?: string }[];
}

export interface TlsModuleResult {
  ok: boolean;
  error?: string;
  skipped?: boolean;
  skipReason?: string;
  source: 'crt.sh' | 'certspotter' | 'unavailable' | 'peer';
  latestCertificate?: {
    issuer: string;
    notBefore: string;
    notAfter: string;
    daysUntilExpiry: number;
    commonName?: string;
    sans: string[];
  };
  recentCount?: number;
  liveTls?: { version?: string; cipher?: string };
  /** The hostname actually searched in CT logs. For IP input this will be the PTR. */
  hostSearched?: string;
}

export interface InferenceModuleResult {
  ok: boolean;
  error?: string;
  cdn?: { detected: boolean; name?: string; evidence: string[] };
  proxyHints: string[];
  asn?: { ip: string; asn?: number; owner?: string; cc?: string; registry?: string };
  originExposureRisk?: { risk: 'none' | 'low' | 'medium' | 'high'; reason: string };
}

export interface IpModuleResult {
  ok: boolean;
  error?: string;
  ip: string;
  version: 'v4' | 'v6';
  scope:
    | 'public'
    | 'private'
    | 'loopback'
    | 'link-local'
    | 'cgnat'
    | 'multicast'
    | 'reserved'
    | 'documentation'
    | 'unspecified'
    | 'benchmark';
  notes: string[];
  anycast?: { likely: boolean; reason: string };
  ptr: string[];
  geo: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
    org?: string;
    isp?: string;
  } | null;
  asn: { asn: number; owner?: string; cc?: string; registry?: string } | null;
}

export interface ShodanService {
  port?: number;
  transport?: string;
  product?: string;
  version?: string;
  cpe: string[];
  hostnames: string[];
  timestamp?: string;
  ssl?: { subjectCn?: string; issuerCn?: string; notBefore?: string; notAfter?: string; versions: string[] };
}

export interface ShodanDomainRecord {
  subdomain?: string;
  type?: string;
  value?: string;
  ports: number[];
  lastSeen?: string;
}

export type ShodanModuleResult =
  | {
      ok: true;
      kind: 'host';
      ip: string;
      skipped?: boolean;
      skipReason?: string;
      hostnames?: string[];
      domains?: string[];
      org?: string;
      isp?: string;
      asn?: string;
      os?: string;
      tags?: string[];
      ports?: number[];
      vulns?: string[];
      lastUpdate?: string;
      services?: ShodanService[];
    }
  | {
      ok: true;
      kind: 'domain';
      domain: string;
      skipped?: boolean;
      skipReason?: string;
      subdomains?: string[];
      tags?: string[];
      records?: ShodanDomainRecord[];
    };

export interface AnalyzeModules {
  dns?: DnsModuleResult;
  http?: HttpModuleResult;
  email?: EmailModuleResult;
  tls?: TlsModuleResult;
  inference?: InferenceModuleResult;
  ip?: IpModuleResult;
  shodan?: ShodanModuleResult;
}

export interface AnalyzeReport {
  input: NormalizedInput;
  summary: {
    title: string;
    riskLevel: 'low' | 'medium' | 'high';
    highlights: string[];
  };
  findings: Finding[];
  modules: AnalyzeModules;
  generatedCommands: string[];
  raw: Record<string, unknown>;
  meta: {
    generatedAt: string;
    durationMs: number;
    version: string;
  };
}

export interface CompareReport {
  a: AnalyzeReport;
  b: AnalyzeReport;
  differences: {
    section: string;
    key: string;
    a?: unknown;
    b?: unknown;
  }[];
  summary: {
    totalDifferences: number;
    notableDifferences: string[];
  };
}
