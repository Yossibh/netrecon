// /api/whoami - returns info about the caller derived from Cloudflare's
// request.cf object and standard headers. No external API calls.

interface CfProps {
  country?: string;
  city?: string;
  region?: string;
  regionCode?: string;
  continent?: string;
  postalCode?: string;
  timezone?: string;
  latitude?: string;
  longitude?: string;
  asn?: number;
  asOrganization?: string;
  colo?: string;
  httpProtocol?: string;
  tlsVersion?: string;
  tlsCipher?: string;
}

function pickUa(ua: string | null): { raw: string; browser: string; os: string } {
  const raw = ua || '';
  let browser = 'unknown';
  let os = 'unknown';
  if (/Edg\//.test(raw)) browser = 'Edge';
  else if (/OPR\/|Opera/.test(raw)) browser = 'Opera';
  else if (/Firefox\//.test(raw)) browser = 'Firefox';
  else if (/Chrome\//.test(raw)) browser = 'Chrome';
  else if (/Safari\//.test(raw)) browser = 'Safari';
  else if (/curl\//i.test(raw)) browser = 'curl';
  else if (/wget/i.test(raw)) browser = 'wget';
  if (/Windows NT/.test(raw)) os = 'Windows';
  else if (/Mac OS X|Macintosh/.test(raw)) os = 'macOS';
  else if (/Android/.test(raw)) os = 'Android';
  else if (/iPhone|iPad|iOS/.test(raw)) os = 'iOS';
  else if (/Linux/.test(raw)) os = 'Linux';
  return { raw, browser, os };
}

export const onRequest: PagesFunction = async ({ request }) => {
  const cf = (request.cf || {}) as CfProps;
  const h = request.headers;
  const ip = h.get('cf-connecting-ip') || h.get('x-forwarded-for') || '';
  const ua = pickUa(h.get('user-agent'));
  const lang = h.get('accept-language') || '';
  const dnt = h.get('dnt') || '';

  const payload = {
    ok: true,
    ip,
    ipVersion: ip.includes(':') ? 6 : ip ? 4 : null,
    network: {
      asn: cf.asn ? `AS${cf.asn}` : null,
      asOrganization: cf.asOrganization || null,
      colo: cf.colo || null,
    },
    geo: {
      country: cf.country || null,
      region: cf.region || null,
      regionCode: cf.regionCode || null,
      city: cf.city || null,
      postalCode: cf.postalCode || null,
      continent: cf.continent || null,
      timezone: cf.timezone || null,
      latitude: cf.latitude ? Number(cf.latitude) : null,
      longitude: cf.longitude ? Number(cf.longitude) : null,
    },
    connection: {
      httpProtocol: cf.httpProtocol || null,
      tlsVersion: cf.tlsVersion || null,
      tlsCipher: cf.tlsCipher || null,
    },
    client: {
      userAgent: ua.raw,
      browser: ua.browser,
      os: ua.os,
      acceptLanguage: lang,
      doNotTrack: dnt || null,
    },
    time: new Date().toISOString(),
  };

  return new Response(JSON.stringify(payload), {
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
    },
  });
};
