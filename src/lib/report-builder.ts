import type { AnalyzeModules, AnalyzeReport, CompareReport, NormalizedInput } from '@/types';
import { detectInput, toProbeUrl } from './input-detection';
import { resolveAll } from './providers/dns';
import { inspectHttp } from './providers/http';
import { analyzeEmail } from './providers/email';
import { inspectTls } from './providers/tls';
import { inferInfrastructure } from './providers/inference';
import { analyzeIp } from './providers/ip';
import { shodanHost, shodanDomain } from './providers/shodan';
import { runFindings, riskLevel } from './findings-engine';
import { generateCommands } from './commands';

const VERSION = '0.1.0';

export interface BuildReportOptions {
  shodanApiKey?: string;
}

export async function buildReport(rawInput: string, opts: BuildReportOptions = {}): Promise<AnalyzeReport> {
  const startedAt = Date.now();
  const input = detectInput(rawInput);

  const modules: AnalyzeModules = {};

  const domain = input.domain;
  const probeUrl = toProbeUrl(input);

  // DNS only makes sense for a domain (or URL with hostname).
  if (domain) {
    modules.dns = await resolveAll(domain).catch((err) => ({
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      records: { A: [], AAAA: [], CNAME: [], MX: [], TXT: [], NS: [], CAA: [], SOA: [] },
      hasIPv6: false,
      hasCAA: false,
    }));
  }

  // IP analysis: bare IP inputs, OR URLs whose host is an IP.
  if (input.ip && input.ipVersion) {
    modules.ip = await analyzeIp(input.ip, input.ipVersion).catch((err) => ({
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      ip: input.ip!,
      version: input.ipVersion!,
      scope: 'public' as const,
      notes: [],
      ptr: [],
      geo: null,
      asn: null,
    }));
  }

  // HTTP + Email run in parallel; TLS waits on HTTP so it can pick up
  // live TLS version/cipher from the probe response.cf.
  const [http, email] = await Promise.all([
    probeUrl
      ? inspectHttp(probeUrl)
      : Promise.resolve({
          ok: false,
          skipped: true,
          skipReason: 'No probe URL derivable from input',
          redirects: [],
          headers: {},
          securityHeaders: {},
          corsHeaders: {},
          cacheHeaders: {},
        } satisfies AnalyzeModules['http']),
    domain
      ? analyzeEmail(domain)
      : Promise.resolve({
          ok: false,
          skipped: true,
          skipReason: 'Email posture requires a domain',
          mxPresent: false,
        } satisfies AnalyzeModules['email']),
  ]);
  const tlsHost = domain ?? modules.ip?.ptr?.[0];
  const tlsBase = tlsHost
    ? await inspectTls(tlsHost, { live: http.liveTls })
    : ({
        ok: true,
        source: 'unavailable',
        skipped: true,
        skipReason: http.liveTls?.version
          ? 'Certificate Transparency logs index by hostname, not IP. Live TLS session metadata from the probe is shown below.'
          : 'TLS inspection requires a domain (CT logs index by hostname, not IP).',
        liveTls: http.liveTls,
      } satisfies AnalyzeModules['tls']);
  const tls: AnalyzeModules['tls'] = { ...tlsBase, hostSearched: tlsHost };
  modules.http = http;
  modules.email = email;
  modules.tls = tls;
  const directIp = modules.ip?.asn
    ? { ip: modules.ip.ip, asn: modules.ip.asn.asn, owner: modules.ip.asn.owner, cc: modules.ip.asn.cc, registry: modules.ip.asn.registry }
    : modules.ip
      ? { ip: modules.ip.ip }
      : undefined;
  modules.inference = await inferInfrastructure(modules.dns, modules.http, directIp);

  // Shodan (paid). Fire only if a key is bound. Per-IP uses the actual IP input
  // or the resolved first A record; per-domain uses the domain.
  if (opts.shodanApiKey) {
    const shodanTargetIp = input.ip ?? modules.dns?.records.A[0]?.data;
    const shodanPromises: Array<Promise<void>> = [];
    if (input.type === 'ip' && shodanTargetIp) {
      shodanPromises.push(
        shodanHost(shodanTargetIp, opts.shodanApiKey).then((r) => { modules.shodan = r; })
      );
    } else if (domain) {
      shodanPromises.push(
        shodanDomain(domain, opts.shodanApiKey).then((r) => { modules.shodan = r; })
      );
    }
    await Promise.all(shodanPromises);
  }

  const findings = runFindings({ input, modules });
  const risk = riskLevel(findings);

  const highlights = buildHighlights(input, modules, findings.length);

  return {
    input,
    summary: {
      title: summaryTitle(input),
      riskLevel: risk,
      highlights,
    },
    findings,
    modules,
    generatedCommands: generateCommands(input),
    raw: {
      dns: modules.dns,
      http: modules.http,
      email: modules.email,
      tls: modules.tls,
      inference: modules.inference,
      ip: modules.ip,
      shodan: modules.shodan,
    },
    meta: {
      generatedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      version: VERSION,
    },
  };
}

function summaryTitle(input: NormalizedInput): string {
  if (input.type === 'domain') return `Report for ${input.domain}`;
  if (input.type === 'ip') return `Report for ${input.ip}`;
  return `Report for ${input.url ?? input.raw}`;
}

function buildHighlights(input: NormalizedInput, modules: AnalyzeModules, findingsCount: number): string[] {
  const out: string[] = [];
  if (modules.ip) {
    const ip = modules.ip;
    if (ip.scope !== 'public') {
      out.push(`IP: ${ip.scope}${ip.notes[0] ? ` (${ip.notes[0]})` : ''}`);
    } else {
      const geo = ip.geo ? `${[ip.geo.city, ip.geo.region, ip.geo.countryCode].filter(Boolean).join(', ')}` : '';
      const asn = ip.asn ? `AS${ip.asn.asn}${ip.asn.owner ? ` ${ip.asn.owner}` : ''}` : '';
      const parts = [geo, asn, ip.ptr[0] ? `PTR ${ip.ptr[0]}` : '', ip.anycast ? 'anycast' : ''].filter(Boolean);
      if (parts.length) out.push(`IP: ${parts.join(' · ')}`);
    }
  }
  if (modules.dns?.ok) {
    out.push(
      `DNS: A=${modules.dns.records.A.length}, AAAA=${modules.dns.records.AAAA.length}, MX=${modules.dns.records.MX.length}, TXT=${modules.dns.records.TXT.length}`
    );
  }
  if (modules.http?.ok) {
    out.push(`HTTP: ${modules.http.status} (${modules.http.redirects.length} redirects, ${modules.http.timingMs}ms)`);
  } else if (modules.http?.error) {
    out.push(`HTTP: ${modules.http.error}`);
  }
  if (modules.inference?.cdn?.detected) {
    out.push(`CDN: ${modules.inference.cdn.name}`);
  }
  if (modules.email?.ok && input.domain) {
    const spf = modules.email.spf?.present ? 'SPF✓' : 'SPF✗';
    const dmarc = modules.email.dmarc?.present ? `DMARC✓(${modules.email.dmarc.policy})` : 'DMARC✗';
    out.push(`Email: ${spf} ${dmarc}`);
  }
  if (modules.tls?.latestCertificate) {
    out.push(`TLS (CT): expires in ${modules.tls.latestCertificate.daysUntilExpiry}d`);
  } else if (modules.tls?.liveTls?.version) {
    out.push(`TLS: ${modules.tls.liveTls.version}${modules.tls.liveTls.cipher ? ' ' + modules.tls.liveTls.cipher : ''}`);
  }
  if (modules.shodan && modules.shodan.ok && !modules.shodan.skipped) {
    const s = modules.shodan;
    if (s.kind === 'host') {
      const ports = s.ports?.length ? `${s.ports.length} ports` : 'no open ports seen';
      const vulns = s.vulns?.length ? `${s.vulns.length} CVEs` : '';
      out.push(`Shodan: ${ports}${vulns ? ' · ' + vulns : ''}${s.org ? ' · ' + s.org : ''}`);
    } else {
      out.push(`Shodan: ${s.subdomains?.length ?? 0} subdomains seen`);
    }
  }
  out.push(`${findingsCount} finding${findingsCount === 1 ? '' : 's'}`);
  return out;
}

// Compare two inputs and diff the interesting sections.
export async function buildComparison(rawA: string, rawB: string, opts: BuildReportOptions = {}): Promise<CompareReport> {
  const [a, b] = await Promise.all([buildReport(rawA, opts), buildReport(rawB, opts)]);
  const diffs: CompareReport['differences'] = [];

  const sections: Array<{ section: string; a: Record<string, unknown>; b: Record<string, unknown> }> = [
    { section: 'dns.counts', a: dnsCounts(a.modules), b: dnsCounts(b.modules) },
    { section: 'http.status', a: { status: a.modules.http?.status, finalUrl: a.modules.http?.finalUrl }, b: { status: b.modules.http?.status, finalUrl: b.modules.http?.finalUrl } },
    { section: 'http.securityHeaders', a: a.modules.http?.securityHeaders ?? {}, b: b.modules.http?.securityHeaders ?? {} },
    { section: 'inference.cdn', a: { name: a.modules.inference?.cdn?.name, detected: a.modules.inference?.cdn?.detected }, b: { name: b.modules.inference?.cdn?.name, detected: b.modules.inference?.cdn?.detected } },
    { section: 'email.posture', a: emailPosture(a.modules), b: emailPosture(b.modules) },
  ];

  for (const s of sections) {
    const keys = new Set([...Object.keys(s.a), ...Object.keys(s.b)]);
    for (const k of keys) {
      const av = s.a[k];
      const bv = s.b[k];
      if (JSON.stringify(av) !== JSON.stringify(bv)) {
        diffs.push({ section: s.section, key: k, a: av, b: bv });
      }
    }
  }

  const notable = diffs
    .filter((d) => ['http.status', 'inference.cdn', 'http.securityHeaders', 'email.posture'].includes(d.section))
    .slice(0, 10)
    .map((d) => `${d.section}.${d.key}: ${JSON.stringify(d.a)} ≠ ${JSON.stringify(d.b)}`);

  return {
    a,
    b,
    differences: diffs,
    summary: {
      totalDifferences: diffs.length,
      notableDifferences: notable,
    },
  };
}

function dnsCounts(m: AnalyzeModules): Record<string, unknown> {
  const r = m.dns?.records;
  if (!r) return {};
  return { A: r.A.length, AAAA: r.AAAA.length, CNAME: r.CNAME.length, MX: r.MX.length, TXT: r.TXT.length, NS: r.NS.length, CAA: r.CAA.length };
}

function emailPosture(m: AnalyzeModules): Record<string, unknown> {
  const e = m.email;
  return {
    spf: e?.spf?.present ?? false,
    spfQualifier: e?.spf?.qualifier,
    dmarc: e?.dmarc?.present ?? false,
    dmarcPolicy: e?.dmarc?.policy,
    mx: e?.mxPresent ?? false,
    mtaSts: e?.mtaSts?.present ?? false,
  };
}
