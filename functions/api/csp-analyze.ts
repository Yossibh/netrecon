import { analyzeCsp } from '../../src/lib/csp-analyzer';
import { validateFetchUrl } from '../../src/lib/security';

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

const USER_AGENT = 'netrecon-csp-analyzer/1.0 (+https://netrecon.pages.dev/csp-analyze)';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json', ...CORS_HEADERS },
  });
}

export const onRequestOptions: PagesFunction = async () =>
  new Response(null, { status: 204, headers: CORS_HEADERS });

export const onRequestGet: PagesFunction = async ({ request }) => {
  const u = new URL(request.url);
  const target = u.searchParams.get('url');
  if (!target) return json({ error: 'Missing required query parameter: url' }, 400);
  return fetchAndAnalyze(target);
};

export const onRequestPost: PagesFunction = async ({ request }) => {
  let body: { url?: string; policy?: string };
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  if (body.policy) {
    return json({ source: 'paste', ...analyzeCsp(body.policy) });
  }
  if (body.url) return fetchAndAnalyze(body.url);
  return json({ error: 'Body must include "url" or "policy"' }, 400);
};

async function fetchAndAnalyze(urlStr: string): Promise<Response> {
  const v = validateFetchUrl(urlStr);
  if (!v.ok) return json({ error: v.reason }, 400);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10_000);
  try {
    const res = await fetch(urlStr, {
      method: 'GET',
      redirect: 'follow',
      signal: ctrl.signal,
      headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml' },
    });
    const headerCsp = res.headers.get('content-security-policy') || '';
    const reportOnly = res.headers.get('content-security-policy-report-only') || '';
    const metaCsp = await extractMetaCsp(res);
    const chosen = headerCsp || metaCsp || reportOnly;
    if (!chosen) {
      return json({
        source: 'fetch',
        fetchedUrl: res.url,
        finalStatus: res.status,
        policy: null,
        error: 'No Content-Security-Policy found in headers or <meta>.',
      });
    }
    return json({
      source: 'fetch',
      fetchedUrl: res.url,
      finalStatus: res.status,
      policySource: headerCsp ? 'response-header' : metaCsp ? 'meta-tag' : 'report-only-header',
      policy: chosen,
      ...analyzeCsp(chosen),
    });
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : String(err) }, 400);
  } finally {
    clearTimeout(timer);
  }
}

async function extractMetaCsp(res: Response): Promise<string> {
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('html')) return '';
  try {
    const text = (await res.text()).slice(0, 200_000);
    const m = text.match(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*content\s*=\s*"([^"]+)"/i);
    if (m) return m[1]!;
    const m2 = text.match(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*content\s*=\s*'([^']+)'/i);
    return m2 ? m2[1]! : '';
  } catch {
    return '';
  }
}
