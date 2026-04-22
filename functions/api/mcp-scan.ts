import { scanMcp } from '../../src/lib/mcp-scanner';
import { validateFetchUrl } from '../../src/lib/security';

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

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
  return runAndRespond(target, null);
};

export const onRequestPost: PagesFunction = async ({ request }) => {
  let body: { url?: string; token?: string };
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  if (!body.url) return json({ error: 'Body must include "url"' }, 400);
  return runAndRespond(body.url, body.token ?? null);
};

async function runAndRespond(urlStr: string, token: string | null): Promise<Response> {
  const v = validateFetchUrl(urlStr);
  if (!v.ok) return json({ error: v.reason }, 400);
  try {
    const report = await scanMcp({ url: urlStr, token: token ?? undefined });
    return json(report);
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : String(err) }, 400);
  }
}
