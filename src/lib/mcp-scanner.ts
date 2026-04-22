// MCP security scanner.
//
// Takes a remote MCP server URL and emits a netrecon-style report:
// transport / auth / semantic / supply-chain findings with severity, evidence,
// next steps, and reproducible commands. Designed to ship inside Workers:
// uses only fetch() + our existing TLS/HTTP providers.

import { inspectTls } from './providers/tls';
import { inspectHttp } from './providers/http';
import type { Finding, Severity } from '@/types';

export interface McpScanOptions {
  url: string;
  token?: string;
  timeoutMs?: number;
}

export interface McpScanReport {
  target: string;
  host: string;
  summary: {
    title: string;
    riskLevel: 'low' | 'medium' | 'high';
    highlights: string[];
    score: number;  // 0..100
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
  };
  findings: Finding[];
  raw: {
    initialize?: unknown;
    toolsList?: unknown;
    unauthenticated?: { status: number; body?: string };
    malformed?: { status: number; body?: string };
    tls?: unknown;
    http?: unknown;
    downgrade?: { attempted: boolean; reachable?: boolean; error?: string };
  };
  meta: {
    generatedAt: string;
    durationMs: number;
    version: string;
  };
}

const DEFAULT_TIMEOUT_MS = 12_000;
const USER_AGENT = 'netrecon-mcp-scanner/1.0 (+https://netrecon.pages.dev/mcp-scan)';

function f(
  id: string,
  severity: Severity,
  title: string,
  explanation: string,
  evidence: string[] = [],
  nextSteps: string[] = [],
  suggestedCommands: string[] = [],
): Finding {
  return { id, severity, title, explanation, evidence, nextSteps, suggestedCommands, module: 'mcp' };
}

export async function scanMcp(opts: McpScanOptions): Promise<McpScanReport> {
  const started = Date.now();
  const url = new URL(opts.url);
  const target = url.toString();
  const host = url.hostname;
  const timeout = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const findings: Finding[] = [];
  const raw: McpScanReport['raw'] = {};

  // ---- 1. Transport: HTTPS required --------------------------------------
  if (url.protocol !== 'https:') {
    findings.push(f(
      'mcp.transport.not-https',
      'high',
      'Server is not using HTTPS',
      'MCP requests include auth tokens, session IDs, and tool payloads. Cleartext HTTP exposes all of them to anyone on the network path.',
      [`URL scheme: ${url.protocol}`],
      ['Put a TLS terminator in front (Cloudflare, Caddy, Nginx).', 'Redirect http -> https permanently.'],
      [`curl -vk ${target}`],
    ));
  }

  // ---- 2. TLS posture (reuse our inspector) ------------------------------
  if (url.protocol === 'https:') {
    try {
      const tls = await inspectTls(host);
      raw.tls = tls;
      const cert = tls.latestCertificate;
      if (tls.ok && cert) {
        if (cert.daysUntilExpiry != null && cert.daysUntilExpiry < 14) {
          findings.push(f(
            'mcp.transport.tls-expiring-soon',
            'high',
            `TLS certificate expires in ${cert.daysUntilExpiry} day(s)`,
            'MCP clients will refuse to connect once the cert expires, taking down every downstream agent that depends on this server.',
            [`notAfter: ${cert.notAfter}`, `issuer: ${cert.issuer}`],
            ['Renew the certificate.', 'Enable auto-renewal (Lets Encrypt, CF origin cert).'],
            [`openssl s_client -connect ${host}:443 -servername ${host} </dev/null 2>/dev/null | openssl x509 -noout -dates`],
          ));
        }
      } else if (!tls.ok) {
        findings.push(f(
          'mcp.transport.tls-unreachable',
          'medium',
          'TLS inspection failed',
          `Could not observe a TLS certificate for ${host}. May indicate a firewall block, wrong port, or a broken cert chain.`,
          [tls.error || 'unknown TLS error'],
          ['Verify the server is reachable on 443 with a valid cert chain.'],
          [`openssl s_client -connect ${host}:443 -servername ${host}`],
        ));
      }
    } catch (err) {
      raw.tls = { error: err instanceof Error ? err.message : String(err) };
    }
  }

  // ---- 3. HTTP headers (reuse our inspector) -----------------------------
  try {
    const http = await inspectHttp(target);
    raw.http = http;
    if (http.ok) {
      const sec = http.securityHeaders || {};
      const cors = http.corsHeaders || {};
      if (cors.accessControlAllowOrigin === '*') {
        findings.push(f(
          'mcp.transport.cors-wildcard',
          'high',
          'CORS Access-Control-Allow-Origin is *',
          'Any website can make requests to this server from a visitor\'s browser. If this server also allows credentials or relies on IP-based auth, any web page the victim visits can invoke tools on their behalf.',
          [`access-control-allow-origin: *`],
          ['Replace * with the specific origin(s) that need browser access.', 'If nothing needs browser access, remove the header entirely.'],
          [`curl -sI -H 'Origin: https://evil.example' ${target}`],
        ));
      }
      if (!sec.hsts) {
        findings.push(f(
          'mcp.transport.no-hsts',
          'medium',
          'Missing Strict-Transport-Security header',
          'Without HSTS, a first-time client can be downgraded to HTTP via an active attacker on the network.',
          [],
          ['Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.'],
          [`curl -sI ${target} | grep -i strict-transport`],
        ));
      }
      if (!sec.xContentTypeOptions) {
        findings.push(f(
          'mcp.transport.no-xcto',
          'low',
          'Missing X-Content-Type-Options header',
          'Not critical for pure API servers, but recommended defense-in-depth. Prevents MIME sniffing if any response is ever browser-rendered.',
          [],
          ['Set `X-Content-Type-Options: nosniff`.'],
        ));
      }
    }
  } catch (err) {
    raw.http = { error: err instanceof Error ? err.message : String(err) };
  }

  // ---- 4. Unauthenticated tools/list -------------------------------------
  const unauthResult = await probeUnauthenticated(target, timeout);
  raw.unauthenticated = unauthResult;
  if (unauthResult.status === 200 && unauthResult.toolsListed) {
    findings.push(f(
      'mcp.auth.open-server',
      'high',
      'Server exposes tools/list without authentication',
      'An unauthenticated GET/POST returned a tool catalog. An open MCP server can be enumerated and invoked by any third party, including malicious AI agents. A Feb 2026 scan found over 8,000 MCP servers in this state.',
      [`tools/list responded 200 with ${unauthResult.toolCount} tool(s)`],
      ['Require a Bearer token for all endpoints.', 'If this is intentional (public docs server), document the exposure explicitly.'],
      [`curl -X POST '${target}' -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`],
    ));
  }

  // ---- 5. Try initializing (possibly authenticated) ---------------------
  const init = await mcpInitialize(target, opts.token, timeout);
  raw.initialize = init.result;
  let tools: any = null;
  let serverName: string | null = null;
  let serverVersion: string | null = null;

  if (init.ok) {
    serverName = init.result?.serverInfo?.name ?? null;
    serverVersion = init.result?.serverInfo?.version ?? null;
    const toolsRes = await mcpToolsList(target, opts.token, init.sessionId, timeout);
    if (toolsRes.ok) {
      tools = toolsRes.result;
      raw.toolsList = toolsRes.result;
    }
  }

  // ---- 6. Known-vulnerable fingerprints (from OX Security 2026 CVEs) ----
  if (serverName) {
    const fp = VULNERABLE_FINGERPRINTS.find((v) => v.match.test(serverName!) || (serverVersion && v.match.test(`${serverName} ${serverVersion}`)));
    if (fp) {
      findings.push(f(
        'mcp.supply-chain.known-vulnerable-fingerprint',
        'high',
        `Server identifies as a product with known MCP CVEs: ${fp.name}`,
        `The server name matches a product disclosed in 2026 MCP supply-chain research. Verify the deployed version is patched.`,
        [`serverInfo.name: ${serverName}`, serverVersion ? `serverInfo.version: ${serverVersion}` : '', `Relevant CVEs: ${fp.cves.join(', ')}`].filter(Boolean),
        [`Review ${fp.name} release notes for fixed versions.`, 'If unpatched, take the server off the public internet until updated.'],
        [],
      ));
    }
  }

  // ---- 7. Semantic scan of tool descriptions -----------------------------
  if (tools && Array.isArray(tools.tools)) {
    for (const t of tools.tools) {
      const hay = `${t.name ?? ''}\n${t.description ?? ''}`;

      // Unicode tag chars (invisible instruction channel)
      if (/[\u{E0000}-\u{E007F}]/u.test(hay)) {
        findings.push(f(
          'mcp.semantic.unicode-tag-chars',
          'high',
          `Tool "${t.name}" contains invisible Unicode tag characters`,
          'Tags-block (U+E0000..U+E007F) codepoints are invisible to humans but included in text handed to LLMs. Attackers embed hidden instructions there to hijack agents (tool-poisoning).',
          [`tool: ${t.name}`],
          ['Strip the tags block from the description.', 'Audit how the description arrived in the catalog.'],
          [],
        ));
      }
      // Zero-width / bidi controls
      if (/[\u200B-\u200F\u202A-\u202E\u2066-\u2069]/.test(hay)) {
        findings.push(f(
          'mcp.semantic.bidi-or-zero-width',
          'medium',
          `Tool "${t.name}" contains zero-width or bidi control characters`,
          'These characters can be used to hide or reorder text presented to humans reviewing the catalog while the model still sees the reordered string.',
          [`tool: ${t.name}`],
          ['Normalize and strip non-printable whitespace before publishing tool metadata.'],
          [],
        ));
      }
      // Classic prompt-injection override phrases
      const phrases = [
        /ignore (all |any |the )?previous instructions?/i,
        /disregard (all |any |the )?(prior|previous|above)/i,
        /\byou are now\b/i,
        /\bsystem:\s/i,
        /<\/?(system|assistant|user)>/i,
      ];
      for (const re of phrases) {
        if (re.test(hay)) {
          findings.push(f(
            'mcp.semantic.prompt-injection-phrase',
            'high',
            `Tool "${t.name}" description contains a prompt-injection override phrase`,
            'The tool metadata contains text that reads as an instruction override when fed to an LLM. Either the author embedded instructions in the description (bad practice) or the catalog has been poisoned.',
            [`tool: ${t.name}`, `pattern: ${re.source}`],
            ['Rewrite the description as a neutral statement of what the tool does.', 'If this came from a public registry, stop using that tool.'],
            [],
          ));
          break;
        }
      }
      // Dangerous parameter names
      const props = (t.inputSchema?.properties ?? {}) as Record<string, any>;
      const danger = ['command', 'cmd', 'exec', 'shell', 'eval', 'script'];
      for (const [k, s] of Object.entries(props)) {
        if (danger.includes(k.toLowerCase()) && (s.type === 'string' || !s.type)) {
          findings.push(f(
            'mcp.semantic.dangerous-parameter',
            'high',
            `Tool "${t.name}" accepts a free-form "${k}" parameter`,
            'A free-form string parameter named like a shell/exec field suggests the server may forward it to a process or interpreter. If so, any agent that reaches this tool can run arbitrary commands (cf. Upsonic CVE-2026-30625, LiteLLM CVE-2026-30623).',
            [`tool: ${t.name}`, `parameter: ${k}`],
            ['Replace free-form commands with an allowlist of actions.', 'If the tool really does need to exec, namespace it and require a scoped credential.'],
            [],
          ));
        }
      }
      // npx / uvx / sudo substrings suggesting unsafe examples
      if (/\b(npx|uvx|pipx)\b\s+-y\b/.test(hay) || /\bcurl .*\|\s*(bash|sh)\b/i.test(hay)) {
        findings.push(f(
          'mcp.semantic.unsafe-install-hint',
          'medium',
          `Tool "${t.name}" description contains unsafe install patterns`,
          'Descriptions that embed `npx -y <pkg>` or `curl | bash` encourage users to run untrusted code. This is the class of pattern that produced the Upsonic allowlist-bypass CVE.',
          [`tool: ${t.name}`],
          ['Remove install hints from tool descriptions; put them in versioned documentation instead.'],
          [],
        ));
      }
    }
  }

  // ---- 8. Error verbosity (malformed request) ----------------------------
  const malformed = await probeMalformed(target, opts.token, timeout);
  raw.malformed = malformed;
  if (malformed.body && /\b(at [A-Z_]+\.[a-z]|\.py:\d+|\/(usr|var|home|opt)\/|[A-Z]:\\|stack trace|internal server error.*\n)/i.test(malformed.body)) {
    findings.push(f(
      'mcp.error.verbose-stack-trace',
      'medium',
      'Server returns stack traces / internal paths on malformed input',
      'A malformed JSON-RPC request produced output that looks like a stack trace or filesystem path. This leaks the tech stack and directory layout of the host and can speed up targeted exploitation.',
      [malformed.body.slice(0, 200)],
      ['Catch and re-serialize errors with a generic message for clients.', 'Log the full trace server-side only.'],
      [],
    ));
  }

  // ---- 9. Transport-type downgrade probe (DocsGPT MITM class) ------------
  if (url.protocol === 'https:') {
    const httpUrl = target.replace(/^https:/, 'http:');
    const downgrade = await probeDowngrade(httpUrl, timeout);
    raw.downgrade = downgrade;
    if (downgrade.reachable) {
      findings.push(f(
        'mcp.supply-chain.transport-downgrade',
        'high',
        'Same endpoint answers over plain HTTP',
        'An MITM on the network can steer a client from https to http and proxy the traffic in cleartext, capturing auth tokens and invoking tools on the client\'s behalf (cf. DocsGPT CVE-2026-26015).',
        [`http:// equivalent responded: HTTP ${downgrade.status}`],
        ['Disable plain-HTTP listening entirely or have it only redirect (301) to https://.', 'Set HSTS so browsers refuse the downgrade even on first contact.'],
        [`curl -vk ${httpUrl}`],
      ));
    }
  }

  // ---- Summary & scoring -------------------------------------------------
  const score = computeScore(findings);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const riskLevel: 'low' | 'medium' | 'high' =
    findings.some((x) => x.severity === 'high') ? 'high' :
    findings.some((x) => x.severity === 'medium') ? 'medium' : 'low';

  const highlights: string[] = [];
  if (serverName) highlights.push(`Server: ${serverName}${serverVersion ? ' v' + serverVersion : ''}`);
  highlights.push(`${tools?.tools?.length ?? 0} tool(s) enumerated`);
  highlights.push(`${findings.filter((x) => x.severity === 'high').length} high · ${findings.filter((x) => x.severity === 'medium').length} medium · ${findings.filter((x) => x.severity === 'low').length} low`);
  highlights.push(`Score ${score}/100 (${grade})`);

  return {
    target,
    host,
    summary: {
      title: `MCP scan of ${host}`,
      riskLevel,
      highlights,
      score,
      grade,
    },
    findings,
    raw,
    meta: {
      generatedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      version: '1.0.0',
    },
  };
}

// ---- Scoring --------------------------------------------------------------
function computeScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    if (f.severity === 'high') score -= 15;
    else if (f.severity === 'medium') score -= 7;
    else if (f.severity === 'low') score -= 3;
  }
  return Math.max(0, score);
}

// ---- Probes ---------------------------------------------------------------
async function probeUnauthenticated(url: string, timeout: number): Promise<{ status: number; body?: string; toolsListed?: boolean; toolCount?: number }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'user-agent': USER_AGENT },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    const text = await safeBody(res);
    let toolsListed = false;
    let toolCount = 0;
    try {
      const parsed = JSON.parse(text);
      if (parsed?.result?.tools && Array.isArray(parsed.result.tools)) {
        toolsListed = true;
        toolCount = parsed.result.tools.length;
      }
    } catch { /* try SSE parse */
      const jsonLine = text.split('\n').find((l) => l.startsWith('data:'));
      if (jsonLine) {
        try {
          const parsed = JSON.parse(jsonLine.slice(5).trim());
          if (parsed?.result?.tools && Array.isArray(parsed.result.tools)) {
            toolsListed = true;
            toolCount = parsed.result.tools.length;
          }
        } catch { /* ignore */ }
      }
    }
    return { status: res.status, body: text.slice(0, 2000), toolsListed, toolCount };
  } catch (err) {
    return { status: 0, body: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(t);
  }
}

async function probeMalformed(url: string, token: string | undefined, timeout: number): Promise<{ status: number; body?: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'user-agent': USER_AGENT };
    if (token) headers.authorization = `Bearer ${token}`;
    const res = await fetch(url, {
      method: 'POST', signal: ctrl.signal, headers,
      body: '{"jsonrpc":"2.0","id":1,"method":"__not_a_real_method__","params":{"a":[1,2,3',  // intentionally broken
    });
    return { status: res.status, body: (await safeBody(res)).slice(0, 2000) };
  } catch (err) {
    return { status: 0, body: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(t);
  }
}

async function probeDowngrade(httpUrl: string, timeout: number): Promise<{ attempted: boolean; reachable?: boolean; status?: number; error?: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(httpUrl, {
      method: 'POST',
      signal: ctrl.signal,
      redirect: 'manual',
      headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': USER_AGENT },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    // 30x -> https is fine; only flag if plain http "answered" with a real response code for the MCP endpoint
    const reachable = res.status >= 200 && res.status < 300;
    return { attempted: true, reachable, status: res.status };
  } catch (err) {
    return { attempted: true, reachable: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(t);
  }
}

async function mcpInitialize(url: string, token: string | undefined, timeout: number): Promise<{ ok: boolean; result?: any; sessionId?: string; error?: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'user-agent': USER_AGENT };
    if (token) headers.authorization = `Bearer ${token}`;
    const res = await fetch(url, {
      method: 'POST', signal: ctrl.signal, headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'netrecon-scan', version: '1.0' } } }),
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const sessionId = res.headers.get('mcp-session-id') ?? undefined;
    const text = await safeBody(res);
    const parsed = parseMaybeSse(text);
    if (parsed?.result) return { ok: true, result: parsed.result, sessionId };
    if (parsed?.error) return { ok: false, error: `${parsed.error.code}: ${parsed.error.message}` };
    return { ok: false, error: 'no parseable response' };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(t);
  }
}

async function mcpToolsList(url: string, token: string | undefined, sessionId: string | undefined, timeout: number): Promise<{ ok: boolean; result?: any; error?: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'user-agent': USER_AGENT };
    if (token) headers.authorization = `Bearer ${token}`;
    if (sessionId) headers['mcp-session-id'] = sessionId;
    const res = await fetch(url, {
      method: 'POST', signal: ctrl.signal, headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const parsed = parseMaybeSse(await safeBody(res));
    if (parsed?.result) return { ok: true, result: parsed.result };
    return { ok: false, error: 'no parseable response' };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(t);
  }
}

function parseMaybeSse(text: string): any | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try { return JSON.parse(trimmed); } catch { return null; }
  }
  // SSE: find first "data:" line with JSON
  for (const line of trimmed.split('\n')) {
    if (line.startsWith('data:')) {
      try { return JSON.parse(line.slice(5).trim()); } catch { /* keep going */ }
    }
  }
  return null;
}

async function safeBody(res: Response): Promise<string> {
  try { return await res.text(); } catch { return ''; }
}

// ---- Known-vulnerable fingerprints (OX Security 2026 disclosures) --------
const VULNERABLE_FINGERPRINTS: Array<{ name: string; match: RegExp; cves: string[] }> = [
  { name: 'GPT Researcher', match: /gpt[-_ ]?researcher/i, cves: ['CVE-2025-65720'] },
  { name: 'LiteLLM', match: /lite[-_ ]?llm/i, cves: ['CVE-2026-30623'] },
  { name: 'Agent Zero', match: /agent[-_ ]?zero/i, cves: ['CVE-2026-30624'] },
  { name: 'Fay Framework', match: /\bfay\b/i, cves: ['CVE-2026-30618'] },
  { name: 'Bisheng', match: /bisheng/i, cves: ['CVE-2026-33224'] },
  { name: 'Langchain-Chatchat', match: /langchain[-_ ]?chat(chat)?/i, cves: ['CVE-2026-30617'] },
  { name: 'Jaaz', match: /\bjaaz\b/i, cves: ['CVE-2026-33224'] },
  { name: 'Upsonic', match: /upsonic/i, cves: ['CVE-2026-30625'] },
  { name: 'Windsurf', match: /windsurf/i, cves: ['CVE-2026-30615'] },
  { name: 'DocsGPT', match: /docs[-_ ]?gpt/i, cves: ['CVE-2026-26015'] },
];
