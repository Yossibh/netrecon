import type { NormalizedInput } from '@/types';

// Pure helpers that produce copy-paste reproduction commands.
// These are emitted alongside findings and in the top-level generatedCommands list.

export function commandsForDomain(domain: string): string[] {
  return [
    `dig A ${domain} +short`,
    `dig AAAA ${domain} +short`,
    `dig MX ${domain} +short`,
    `dig NS ${domain} +short`,
    `dig CAA ${domain} +short`,
    `dig TXT ${domain} +short`,
    `dig TXT _dmarc.${domain} +short`,
    `dig TXT _mta-sts.${domain} +short`,
    `nslookup -type=ANY ${domain}`,
    `openssl s_client -connect ${domain}:443 -servername ${domain} </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates -ext subjectAltName`,
    `curl -sSI https://${domain}`,
    `curl -sS -o /dev/null -w "%{http_code} %{url_effective}\\n" -L https://${domain}`,
  ];
}

export function commandsForIp(ip: string, ipVersion: 'v4' | 'v6' | undefined): string[] {
  const cmds = [
    `whois ${ip}`,
    `dig -x ${ip} +short`,
    ipVersion === 'v6' ? `traceroute -6 ${ip}` : `traceroute ${ip}`,
    ipVersion === 'v6' ? `mtr -6 -rwc 10 ${ip}` : `mtr -rwc 10 ${ip}`,
  ];
  if (ipVersion === 'v4') {
    cmds.push(`curl -sSI http://${ip}/`);
    cmds.push(`curl -sSIk https://${ip}/`);
    cmds.push(`openssl s_client -connect ${ip}:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates`);
  }
  if (ipVersion === 'v6') {
    cmds.push(`curl -sSI -g 'http://[${ip}]/'`);
    cmds.push(`curl -sSIk -g 'https://[${ip}]/'`);
  }
  return cmds;
}

export function commandsForUrl(url: string): string[] {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return [];
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  return [
    `curl -sSI -L ${url}`,
    `curl -sS -o /dev/null -w "%{http_code} %{url_effective} (%{time_total}s)\\n" -L ${url}`,
    `openssl s_client -connect ${host}:${u.port || 443} -servername ${host} </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer -subject`,
    `dig A ${host} +short`,
  ];
}

export function generateCommands(input: NormalizedInput): string[] {
  const out = new Set<string>();
  if (input.domain) for (const c of commandsForDomain(input.domain)) out.add(c);
  if (input.ip) for (const c of commandsForIp(input.ip, input.ipVersion)) out.add(c);
  if (input.url) for (const c of commandsForUrl(input.url)) out.add(c);
  return [...out];
}
