import { describe, it, expect } from 'vitest';
import {
  buildAxfrQuery,
  buildDnsMessage,
  classify,
  encodeLabels,
  parseDnsHeader,
} from '../src/lib/providers/axfr';

describe('encodeLabels', () => {
  it('encodes a simple domain', () => {
    const out = encodeLabels('example.com');
    // 7 "example" = \x07 e x a m p l e  \x03 c o m  \x00 = 13 bytes
    expect(out.length).toBe(13);
    expect(out[0]).toBe(7);
    expect(out[8]).toBe(3);
    expect(out[12]).toBe(0);
  });
  it('strips trailing dot', () => {
    expect(encodeLabels('a.b.').length).toBe(encodeLabels('a.b').length);
  });
  it('rejects oversize labels (>63 chars)', () => {
    expect(() => encodeLabels('x'.repeat(64) + '.com')).toThrow();
  });
});

describe('buildDnsMessage + buildAxfrQuery', () => {
  it('produces a valid AXFR query with 2-byte length prefix', () => {
    const q = buildAxfrQuery('example.com');
    const len = (q[0]! << 8) | q[1]!;
    expect(q.length).toBe(2 + len);
    // qdcount == 1 at offset 4-5 of DNS message (offset 6-7 in framed)
    const qdcount = (q[2 + 4]! << 8) | q[2 + 5]!;
    expect(qdcount).toBe(1);
    // qtype at offset -4 from end = 252
    const qtype = (q[q.length - 4]! << 8) | q[q.length - 3]!;
    expect(qtype).toBe(252);
    // qclass at offset -2 from end = 1 (IN)
    const qclass = (q[q.length - 2]! << 8) | q[q.length - 1]!;
    expect(qclass).toBe(1);
  });

  it('sets flags to 0 (not recursive, opcode 0)', () => {
    const msg = buildDnsMessage('a.b.c', 252, 1);
    expect(msg[2]).toBe(0);
    expect(msg[3]).toBe(0);
  });
});

describe('parseDnsHeader', () => {
  it('parses a minimal NOERROR with 1 answer', () => {
    const h = new Uint8Array(12);
    h[0] = 0xab; h[1] = 0xcd;
    h[2] = 0x84; // QR=1, AA=1
    h[3] = 0x00; // RCODE=0 (NOERROR)
    h[6] = 0x00; h[7] = 0x01; // ANCOUNT=1
    const hdr = parseDnsHeader(h)!;
    expect(hdr.qr).toBe(true);
    expect(hdr.aa).toBe(true);
    expect(hdr.rcode).toBe(0);
    expect(hdr.ancount).toBe(1);
  });

  it('parses REFUSED', () => {
    const h = new Uint8Array(12);
    h[2] = 0x80;
    h[3] = 0x05;
    const hdr = parseDnsHeader(h)!;
    expect(hdr.rcode).toBe(5);
  });

  it('returns null for too-short input', () => {
    expect(parseDnsHeader(new Uint8Array(5))).toBeNull();
  });
});

describe('classify', () => {
  const mkHdr = (rcode: number, ancount: number) => {
    const b = new Uint8Array(12);
    b[3] = rcode & 0x0f;
    b[6] = (ancount >> 8) & 0xff;
    b[7] = ancount & 0xff;
    return parseDnsHeader(b)!;
  };

  it('classifies NOERROR + ancount>0 as open', () => {
    expect(classify('ns1.x', mkHdr(0, 3), 42).status).toBe('open');
  });
  it('classifies REFUSED as refused', () => {
    expect(classify('ns1.x', mkHdr(5, 0), 42).status).toBe('refused');
  });
  it('classifies NOTAUTH as refused', () => {
    expect(classify('ns1.x', mkHdr(9, 0), 42).status).toBe('refused');
  });
  it('classifies NOERROR + ancount=0 as other (ambiguous)', () => {
    expect(classify('ns1.x', mkHdr(0, 0), 42).status).toBe('other');
  });
  it('attaches rcodeName for readability', () => {
    expect(classify('ns1.x', mkHdr(5, 0), 1).rcodeName).toBe('REFUSED');
  });
});
