import { buildReport } from '../../src/lib/report-builder';

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...CORS_HEADERS },
  });
}

type Env = { SHODAN_API_KEY?: string };

export const onRequestOptions: PagesFunction<Env> = async () =>
  new Response(null, { status: 204, headers: CORS_HEADERS });

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const url = new URL(request.url);
  const input = url.searchParams.get('input');
  if (!input) return json({ error: 'Missing required query parameter: input' }, 400);
  return runAndRespond(input, env);
};

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: { input?: string } = {};
  try {
    body = (await request.json()) as { input?: string };
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }
  if (!body.input) return json({ error: 'Body must include "input"' }, 400);
  return runAndRespond(body.input, env);
};

async function runAndRespond(input: string, env: Env): Promise<Response> {
  try {
    const report = await buildReport(input, { shodanApiKey: env.SHODAN_API_KEY });
    return json(report);
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : String(err) }, 400);
  }
}
