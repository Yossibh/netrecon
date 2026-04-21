// X.509 field extraction.
//
// We use `pkijs` / `asn1js` rather than hand-rolling an ASN.1/DER parser,
// because X.509 is a well-known footgun (long-form lengths, string types,
// extension encoding, SAN formats, etc.). Both libraries are browser- and
// WebCrypto-friendly and work in Cloudflare Workers.

import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';

export interface ExtractedCert {
  subject: string;           // CN or best-effort DN
  issuer: string;            // CN or best-effort DN
  notBefore: string;         // ISO-8601
  notAfter: string;          // ISO-8601
  sans: string[];            // DNS names + IPs from subjectAltName
  signatureAlgorithm: string; // human name where known, else OID
  publicKeyAlgorithm: string; // human name where known, else OID
  serialNumber: string;      // hex, lowercase, no separators
  fingerprintSha256: string; // lowercase hex, no separators
  selfSigned: boolean;
  expired: boolean;          // as of now
  daysUntilExpiry: number;   // negative if expired
}

// Minimal OID -> friendly name lookup. Everything unrecognised falls through
// to the raw OID so nothing silently becomes wrong.
const OID_NAMES: Record<string, string> = {
  '2.5.4.3':            'CN',
  '2.5.4.6':            'C',
  '2.5.4.7':            'L',
  '2.5.4.8':            'ST',
  '2.5.4.10':           'O',
  '2.5.4.11':           'OU',
  '1.2.840.113549.1.1.1':  'rsaEncryption',
  '1.2.840.113549.1.1.5':  'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassa-pss',
  '1.2.840.10045.2.1':     'ecPublicKey',
  '1.2.840.10045.4.3.2':   'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3':   'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4':   'ecdsa-with-SHA512',
  '1.3.101.112':           'Ed25519',
  '1.3.101.113':           'Ed448',
};

function oidName(oid: string): string { return OID_NAMES[oid] ?? oid; }

function rdnToDn(rdnSequence: any): { cn: string; dn: string } {
  let cn = '';
  const parts: string[] = [];
  const arr = rdnSequence?.typesAndValues ?? [];
  for (const tv of arr) {
    const type = String(tv.type);
    const label = oidName(type);
    let value = '';
    const v = tv.value;
    if (v && typeof v.valueBlock?.value === 'string') value = v.valueBlock.value;
    else if (v && typeof v.toString === 'function') value = String(v);
    if (type === '2.5.4.3') cn = value;
    parts.push(`${label}=${value}`);
  }
  // Fallback: pkijs has been observed to populate typesAndValues=[] for the
  // issuer RDN on certain CloudFront / Cloudflare-edge certificates even
  // though `valueBeforeDecode` still holds the raw DER. When that happens
  // we re-parse the raw bytes ourselves by walking the ASN.1 tree.
  if (arr.length === 0 && rdnSequence?.valueBeforeDecode) {
    const raw: ArrayBuffer | undefined = rdnSequence.valueBeforeDecode;
    try {
      // A Name is SEQUENCE OF SET OF SEQUENCE{OID, value}. asn1js gives us
      // the outer SEQUENCE; each element is a SET (RelativeDistinguishedName)
      // whose element is a SEQUENCE(AttributeTypeAndValue).
      const outer = asn1js.fromBER(raw);
      if (outer.offset !== -1) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const rdnSeq: any = outer.result;
        // If the raw bytes *are* the Name (SEQUENCE) itself, its valueBlock.value
        // is the array of RDN SETs. Some pkijs builds instead give back the
        // inner contents directly — accept both shapes.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const rdns: any[] = rdnSeq?.valueBlock?.value ?? [];
        for (const rdn of rdns) {
          // rdn is a SET, whose valueBlock.value is an array of AttributeTypeAndValue SEQUENCEs.
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const attrs: any[] = rdn?.valueBlock?.value ?? [];
          for (const attr of attrs) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const items: any[] = attr?.valueBlock?.value ?? [];
            if (items.length < 2) continue;
            const oidBlock = items[0];
            const valBlock = items[1];
            // asn1js ObjectIdentifier stores string in .valueBlock.toString() or .getValue()
            let oid = '';
            try { oid = String(oidBlock?.valueBlock?.toString?.() ?? oidBlock?.getValue?.() ?? ''); } catch {}
            if (!oid && oidBlock?.valueBlock?.value) {
              // some builds keep .value as the dotted string
              oid = String(oidBlock.valueBlock.value);
            }
            // Strings come as PrintableString / UTF8String / etc. Their
            // decoded text is at .valueBlock.value.
            let value = '';
            if (valBlock?.valueBlock?.value !== undefined && typeof valBlock.valueBlock.value === 'string') {
              value = valBlock.valueBlock.value;
            } else if (typeof valBlock?.toString === 'function') {
              // Best-effort for other string types.
              const s = String(valBlock);
              // Strip pkijs' "UTF8String : foo" / "PrintableString : foo" prefix.
              const m = /: (.+)$/.exec(s);
              value = m ? m[1]! : s;
            }
            const label = oidName(oid);
            if (oid === '2.5.4.3') cn = value;
            parts.push(`${label}=${value}`);
          }
        }
      }
    } catch { /* swallow — leaves parts empty, caller handles */ }
  }
  return { cn, dn: parts.join(', ') };
}

function bytesToHex(bytes: Uint8Array | ArrayBuffer): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '';
  for (let i = 0; i < u.length; i++) out += (u[i]! < 16 ? '0' : '') + u[i]!.toString(16);
  return out;
}

async function sha256Hex(der: Uint8Array): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  return bytesToHex(new Uint8Array(h));
}

function extractSans(cert: Certificate): string[] {
  const exts = cert.extensions ?? [];
  const sanExt = exts.find((e) => e.extnID === '2.5.29.17');
  if (!sanExt) return [];
  const parsed = sanExt.parsedValue;
  // pkijs exposes the SAN as an `AltName` with .altNames array of GeneralName.
  const altNames: any[] = parsed?.altNames ?? [];
  const out: string[] = [];
  for (const g of altNames) {
    // GeneralName types by tag class context [0..8]
    const t = g.type;
    const v = g.value;
    if (t === 2) out.push(String(v));                                 // dNSName
    else if (t === 7 && v) {                                          // iPAddress
      // pkijs returns an OctetString. Length determines v4 vs v6.
      const raw: Uint8Array = v.valueBlock?.valueHexView ?? new Uint8Array();
      if (raw.length === 4) out.push(`${raw[0]}.${raw[1]}.${raw[2]}.${raw[3]}`);
      else if (raw.length === 16) {
        const parts: string[] = [];
        for (let i = 0; i < 16; i += 2) parts.push(((raw[i]! << 8) | raw[i + 1]!).toString(16));
        out.push(parts.join(':'));
      }
    } else if (t === 1) out.push(String(v));                          // rfc822Name
    else if (t === 6) out.push(String(v));                            // uniformResourceIdentifier
  }
  return out;
}

/** Parse a DER-encoded X.509 certificate and extract the fields we surface. */
export async function extractCertFields(der: Uint8Array): Promise<ExtractedCert> {
  const ab = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength);
  const asn = asn1js.fromBER(ab);
  if (asn.offset === -1) throw new Error(`DER parse failed: ${asn.result.error}`);
  const cert = new Certificate({ schema: asn.result });

  const subject = rdnToDn(cert.subject);
  const issuer  = rdnToDn(cert.issuer);

  const notBefore = cert.notBefore.value instanceof Date
    ? cert.notBefore.value.toISOString() : new Date(cert.notBefore.value as any).toISOString();
  const notAfter = cert.notAfter.value instanceof Date
    ? cert.notAfter.value.toISOString() : new Date(cert.notAfter.value as any).toISOString();

  const sans = extractSans(cert);

  const sigOid = String(cert.signatureAlgorithm.algorithmId);
  const pkOid  = String(cert.subjectPublicKeyInfo.algorithm.algorithmId);

  const serialBytes: Uint8Array = cert.serialNumber.valueBlock.valueHexView ?? new Uint8Array();
  const fp = await sha256Hex(der);

  const now = Date.now();
  const nbMs = new Date(notBefore).getTime();
  const naMs = new Date(notAfter).getTime();
  const expired = !(now >= nbMs && now <= naMs);
  const daysUntilExpiry = Math.floor((naMs - now) / (1000 * 60 * 60 * 24));

  return {
    subject: subject.cn || subject.dn,
    issuer:  issuer.cn  || issuer.dn,
    notBefore,
    notAfter,
    sans,
    signatureAlgorithm: oidName(sigOid),
    publicKeyAlgorithm: oidName(pkOid),
    serialNumber: bytesToHex(serialBytes),
    fingerprintSha256: fp,
    selfSigned: subject.dn === issuer.dn && subject.dn !== '',
    expired,
    daysUntilExpiry,
  };
}

/** Check if any SAN / subject CN matches the requested SNI hostname (wildcards OK). */
export function matchesHostname(cert: ExtractedCert, host: string): boolean {
  const h = host.toLowerCase();
  const candidates = [...cert.sans];
  if (cert.subject && !cert.subject.includes('=')) candidates.push(cert.subject);
  for (const raw of candidates) {
    const c = raw.toLowerCase();
    if (c === h) return true;
    if (c.startsWith('*.')) {
      const suffix = c.slice(1);
      // wildcard only matches one label, not arbitrarily deep
      if (h.endsWith(suffix) && h.slice(0, -suffix.length).indexOf('.') === -1) return true;
    }
  }
  return false;
}
