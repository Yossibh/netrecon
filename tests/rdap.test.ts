import { describe, it, expect } from 'vitest';
import { parseRdapDomain } from '../src/lib/providers/rdap';

describe('parseRdapDomain', () => {
  it('parses a well-formed RDAP response', () => {
    const body = {
      ldhName: 'example.com',
      handle: '2336799_DOMAIN_COM-VRSN',
      status: ['client delete prohibited', 'client transfer prohibited'],
      events: [
        { eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' },
        { eventAction: 'expiration', eventDate: '2099-08-13T04:00:00Z' },
        { eventAction: 'last changed', eventDate: '2024-08-14T07:01:34Z' },
      ],
      nameservers: [{ ldhName: 'A.IANA-SERVERS.NET' }, { ldhName: 'B.IANA-SERVERS.NET' }],
      secureDNS: { delegationSigned: true },
      entities: [
        {
          roles: ['registrar'],
          vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'RESERVED-Internet Assigned Numbers Authority']]],
          entities: [
            {
              roles: ['abuse'],
              vcardArray: ['vcard', [['fn', {}, 'text', 'Abuse Contact'], ['email', {}, 'text', 'abuse@iana.org']]],
            },
          ],
        },
      ],
    };
    const r = parseRdapDomain('example.com', body);
    expect(r.ok).toBe(true);
    expect(r.registrar).toBe('RESERVED-Internet Assigned Numbers Authority');
    expect(r.abuseEmail).toBe('abuse@iana.org');
    expect(r.registeredAt).toBe('1995-08-14T04:00:00Z');
    expect(r.expiresAt).toBe('2099-08-13T04:00:00Z');
    expect(r.nameservers).toEqual(['a.iana-servers.net', 'b.iana-servers.net']);
    expect(r.dnssecSigned).toBe(true);
    expect(r.daysUntilExpiry).toBeGreaterThan(10_000);
  });

  it('computes negative daysUntilExpiry for expired domains', () => {
    const body = {
      events: [{ eventAction: 'expiration', eventDate: '2001-01-01T00:00:00Z' }],
    };
    const r = parseRdapDomain('old.example', body);
    expect(r.daysUntilExpiry).toBeLessThan(0);
  });

  it('handles empty / minimal response', () => {
    const r = parseRdapDomain('x.y', {});
    expect(r.ok).toBe(true);
    expect(r.registrar).toBeUndefined();
    expect(r.expiresAt).toBeUndefined();
    expect(r.nameservers).toEqual([]);
    expect(r.daysUntilExpiry).toBeNull();
  });
});
