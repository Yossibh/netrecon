import type { RdapModuleResult } from '@/types';

// RDAP bootstrap: rdap.org redirects to the authoritative RDAP server for the
// TLD without us having to maintain the IANA bootstrap list ourselves.
const RDAP_DOMAIN_BASE = 'https://rdap.org/domain/';
const TIMEOUT_MS = 6_000;

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: unknown[];
  entities?: RdapEntity[];
}

interface RdapDomainResponse {
  ldhName?: string;
  unicodeName?: string;
  handle?: string;
  status?: string[];
  events?: RdapEvent[];
  nameservers?: Array<{ ldhName?: string }>;
  entities?: RdapEntity[];
  secureDNS?: { delegationSigned?: boolean };
}

export async function lookupDomainRdap(domain: string): Promise<RdapModuleResult> {
  const url = `${RDAP_DOMAIN_BASE}${encodeURIComponent(domain)}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { accept: 'application/rdap+json, application/json' },
    });
    if (res.status === 404) {
      return {
        ok: true,
        skipped: true,
        skipReason: `RDAP has no record for ${domain} (404). Likely not registered, or the TLD is not in the IANA RDAP bootstrap.`,
        domain,
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: `RDAP HTTP ${res.status}`,
        domain,
      };
    }
    const body = (await res.json()) as RdapDomainResponse;
    return parseRdapDomain(domain, body);
  } catch (err) {
    const isAbort = err instanceof Error && (err.name === 'AbortError' || /aborted/i.test(err.message));
    return {
      ok: false,
      error: isAbort ? `RDAP timed out after ${TIMEOUT_MS}ms` : err instanceof Error ? err.message : String(err),
      domain,
    };
  } finally {
    clearTimeout(timer);
  }
}

export function parseRdapDomain(domain: string, body: RdapDomainResponse): RdapModuleResult {
  const events = body.events ?? [];
  const dateOf = (action: string): string | undefined =>
    events.find((e) => e.eventAction?.toLowerCase() === action.toLowerCase())?.eventDate;

  const registration = dateOf('registration');
  const expiration = dateOf('expiration');
  const lastChanged = dateOf('last changed') ?? dateOf('last update of rdap database');

  let daysUntilExpiry: number | null = null;
  if (expiration) {
    const exp = Date.parse(expiration);
    if (!Number.isNaN(exp)) {
      daysUntilExpiry = Math.floor((exp - Date.now()) / 86_400_000);
    }
  }

  const registrar = extractRegistrar(body.entities);
  const abuseEmail = extractAbuseEmail(body.entities);
  const nameservers = (body.nameservers ?? [])
    .map((n) => (n.ldhName ?? '').toLowerCase().replace(/\.$/, ''))
    .filter(Boolean)
    .sort();

  return {
    ok: true,
    domain,
    ldhName: body.ldhName ?? domain,
    handle: body.handle,
    status: body.status ?? [],
    registrar,
    abuseEmail,
    registeredAt: registration,
    expiresAt: expiration,
    lastChangedAt: lastChanged,
    daysUntilExpiry,
    nameservers,
    dnssecSigned: body.secureDNS?.delegationSigned,
  };
}

function extractRegistrar(entities: RdapEntity[] | undefined): string | undefined {
  for (const e of walkEntities(entities)) {
    if (!e.roles?.some((r) => r.toLowerCase() === 'registrar')) continue;
    const fn = fnFromVcard(e.vcardArray);
    if (fn) return fn;
  }
  return undefined;
}

function extractAbuseEmail(entities: RdapEntity[] | undefined): string | undefined {
  for (const e of walkEntities(entities)) {
    if (!e.roles?.some((r) => r.toLowerCase() === 'abuse')) continue;
    const email = emailFromVcard(e.vcardArray);
    if (email) return email;
  }
  return undefined;
}

function* walkEntities(entities: RdapEntity[] | undefined): Generator<RdapEntity> {
  if (!entities) return;
  for (const e of entities) {
    yield e;
    if (e.entities) yield* walkEntities(e.entities);
  }
}

// vcardArray shape: ["vcard", [["fn",{},"text","Example Registrar"], ["email",{},"text","abuse@x.com"], ...]]
function fnFromVcard(vcard: unknown[] | undefined): string | undefined {
  const prop = findVcardProp(vcard, 'fn');
  return typeof prop?.[3] === 'string' ? (prop[3] as string) : undefined;
}

function emailFromVcard(vcard: unknown[] | undefined): string | undefined {
  const prop = findVcardProp(vcard, 'email');
  return typeof prop?.[3] === 'string' ? (prop[3] as string) : undefined;
}

function findVcardProp(vcard: unknown[] | undefined, name: string): unknown[] | undefined {
  if (!Array.isArray(vcard)) return undefined;
  const props = vcard[1];
  if (!Array.isArray(props)) return undefined;
  for (const p of props) {
    if (Array.isArray(p) && p[0] === name) return p;
  }
  return undefined;
}
