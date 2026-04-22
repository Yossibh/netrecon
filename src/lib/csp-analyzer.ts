// Content-Security-Policy analyzer.
// Pure-function: takes a CSP string, returns directives + findings.
// No network access; safe to call from the browser or a Worker.

import type { Finding, Severity } from '@/types';

export interface CspDirective {
  name: string;
  sources: string[];
}

export interface CspAnalysis {
  directives: CspDirective[];
  findings: Finding[];
  summary: {
    title: string;
    riskLevel: 'low' | 'medium' | 'high';
    score: number;
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
  };
}

const FETCH_DIRECTIVES = new Set([
  'default-src', 'script-src', 'script-src-elem', 'script-src-attr',
  'style-src', 'style-src-elem', 'style-src-attr',
  'img-src', 'font-src', 'connect-src', 'media-src', 'object-src',
  'frame-src', 'child-src', 'worker-src', 'manifest-src', 'prefetch-src',
]);

export function parseCsp(policy: string): CspDirective[] {
  return policy
    .split(';')
    .map((chunk) => chunk.trim())
    .filter(Boolean)
    .map((chunk) => {
      const parts = chunk.split(/\s+/);
      const name = (parts[0] || '').toLowerCase();
      const sources = parts.slice(1);
      return { name, sources };
    })
    .filter((d) => d.name);
}

function f(id: string, severity: Severity, title: string, explanation: string, evidence: string[] = [], nextSteps: string[] = []): Finding {
  return { id, severity, title, explanation, evidence, nextSteps, suggestedCommands: [], module: 'csp' };
}

export function analyzeCsp(policy: string): CspAnalysis {
  const directives = parseCsp(policy);
  const byName = new Map<string, CspDirective>();
  for (const d of directives) byName.set(d.name, d);
  const findings: Finding[] = [];

  const hasDefault = byName.has('default-src');
  if (!hasDefault) {
    findings.push(f(
      'csp.no-default-src',
      'medium',
      'Missing default-src directive',
      'Without default-src, unlisted fetch directives inherit the browser default (no restriction). Set default-src to a safe fallback like `\'self\'` or `\'none\'`.',
      [],
      ["Add `default-src 'self'` (or `'none'`) as the fallback.", 'Then explicitly widen only the directives that need it.'],
    ));
  }

  // Check each script/style/fetch-like directive for unsafe sources.
  for (const d of directives) {
    if (!FETCH_DIRECTIVES.has(d.name)) continue;
    const isScriptLike = d.name.startsWith('script-src') || d.name === 'default-src';
    const isStyleLike = d.name.startsWith('style-src');

    for (const src of d.sources) {
      const s = src.toLowerCase();
      if (s === "'unsafe-inline'" && (isScriptLike || isStyleLike)) {
        findings.push(f(
          `csp.unsafe-inline.${d.name}`,
          isScriptLike ? 'high' : 'medium',
          `${d.name} allows 'unsafe-inline'`,
          'Inline scripts/styles defeat most of CSP\'s XSS protection. Use nonces or hashes instead.',
          [`${d.name}: ${d.sources.join(' ')}`],
          ["Remove 'unsafe-inline'.", 'Emit per-request nonces on <script> / <style> tags.', 'Or pre-compute hashes of inline blocks with `\'sha256-...\'`.'],
        ));
      }
      if (s === "'unsafe-eval'" && isScriptLike) {
        findings.push(f(
          `csp.unsafe-eval.${d.name}`,
          'high',
          `${d.name} allows 'unsafe-eval'`,
          'eval(), new Function(), setTimeout(string) become possible, which many XSS payloads rely on. Remove unless a library really needs it.',
          [`${d.name}: ${d.sources.join(' ')}`],
          ["Remove 'unsafe-eval'.", 'Replace libraries that depend on dynamic code eval (e.g. old template engines).'],
        ));
      }
      if (s === "'unsafe-hashes'" && isScriptLike) {
        findings.push(f(
          `csp.unsafe-hashes.${d.name}`,
          'medium',
          `${d.name} uses 'unsafe-hashes'`,
          'unsafe-hashes lets hashed scripts run as event handlers (onclick="..."), a common XSS channel. Prefer nonces on separate <script> tags.',
          [],
          ['Move inline event handlers to addEventListener() bound in a nonce\'d <script>.'],
        ));
      }
      if (s === '*' && isScriptLike) {
        findings.push(f(
          `csp.wildcard.${d.name}`,
          'high',
          `${d.name} includes wildcard '*'`,
          'A literal `*` in a script-capable directive allows any origin to serve code. Attackers with any HTTPS host can bypass the CSP.',
          [`${d.name}: ${d.sources.join(' ')}`],
          ['Replace `*` with the explicit origin list you actually need.'],
        ));
      }
      if ((s === 'https:' || s === 'http:' || s === 'data:') && isScriptLike) {
        findings.push(f(
          `csp.scheme-source.${d.name}.${s.replace(':', '')}`,
          s === 'https:' ? 'medium' : 'high',
          `${d.name} allows the entire '${src}' scheme`,
          'Scheme-only sources let any host under that scheme serve scripts. `data:` in script-src is especially dangerous - it lets inline base64 payloads execute.',
          [`${d.name}: ${d.sources.join(' ')}`],
          [`Replace '${src}' with explicit hostnames.`],
        ));
      }
    }

    // nonce + unsafe-inline conflict: modern browsers ignore unsafe-inline when a nonce is present, but older Safari does not.
    const hasNonce = d.sources.some((s) => s.toLowerCase().startsWith("'nonce-"));
    const hasUnsafeInline = d.sources.some((s) => s.toLowerCase() === "'unsafe-inline'");
    if (hasNonce && hasUnsafeInline && (isScriptLike || isStyleLike)) {
      findings.push(f(
        `csp.nonce-and-unsafe-inline.${d.name}`,
        'low',
        `${d.name} has both a nonce and 'unsafe-inline'`,
        "The 'unsafe-inline' token is ignored in browsers that honor the nonce, but it's confusing and silently weakens older clients (Safari < 15.4).",
        [],
        ["Drop 'unsafe-inline' from this directive; keep the nonce."],
      ));
    }

    // Missing strict-dynamic for CSP3 script-src -> informational
    if (d.name === 'script-src' && hasNonce && !d.sources.some((s) => s.toLowerCase() === "'strict-dynamic'")) {
      findings.push(f(
        'csp.no-strict-dynamic',
        'info',
        "script-src has a nonce but no 'strict-dynamic'",
        "Adding 'strict-dynamic' lets nonce-approved scripts load their own dependencies without listing every CDN. Usually a net tightening.",
        [],
        ["Consider adding 'strict-dynamic' so you can drop long host allowlists."],
      ));
    }
  }

  // frame-ancestors / clickjacking
  if (!byName.has('frame-ancestors')) {
    findings.push(f(
      'csp.no-frame-ancestors',
      'medium',
      'Missing frame-ancestors directive',
      "frame-ancestors controls who can iframe your page. X-Frame-Options is the legacy equivalent but CSP wins when both are set.",
      [],
      ["Add `frame-ancestors 'none'` (or `'self'`) to prevent clickjacking."],
    ));
  } else {
    const fa = byName.get('frame-ancestors')!;
    if (fa.sources.includes('*')) {
      findings.push(f(
        'csp.frame-ancestors-wildcard',
        'high',
        'frame-ancestors allows any origin',
        'Any site can iframe your page, enabling clickjacking.',
        [fa.sources.join(' ')],
        ["Restrict to `'self'` or an explicit allowlist."],
      ));
    }
  }

  // object-src
  if (!byName.has('object-src') && !hasDefault) {
    findings.push(f(
      'csp.no-object-src',
      'low',
      'Missing object-src directive',
      'Without object-src and without default-src, <object>/<embed>/<applet> can load from any origin. Legacy attack surface.',
      [],
      ["Add `object-src 'none'`."],
    ));
  }

  // base-uri
  if (!byName.has('base-uri')) {
    findings.push(f(
      'csp.no-base-uri',
      'low',
      'Missing base-uri directive',
      "An attacker with HTML-injection can insert `<base href='...'>` to redirect relative URLs. base-uri locks this down.",
      [],
      ["Add `base-uri 'self'` (or `'none'`)."],
    ));
  }

  // reporting
  if (!byName.has('report-uri') && !byName.has('report-to')) {
    findings.push(f(
      'csp.no-reporting',
      'info',
      'No CSP violation reporting configured',
      "Without report-to / report-uri you never learn about real violations in production. Informational only.",
      [],
      ['Set up a report-to endpoint (e.g. report-uri.com or a self-hosted collector).'],
    ));
  }

  const score = computeCspScore(findings);
  const grade: 'A' | 'B' | 'C' | 'D' | 'F' = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const riskLevel: 'low' | 'medium' | 'high' =
    findings.some((x) => x.severity === 'high') ? 'high' :
    findings.some((x) => x.severity === 'medium') ? 'medium' : 'low';

  return {
    directives,
    findings,
    summary: {
      title: `${directives.length} directive(s) · ${findings.length} finding(s)`,
      riskLevel,
      score,
      grade,
    },
  };
}

function computeCspScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    if (f.severity === 'high') score -= 18;
    else if (f.severity === 'medium') score -= 8;
    else if (f.severity === 'low') score -= 3;
  }
  return Math.max(0, score);
}
