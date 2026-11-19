// SPDX-License-Identifier: AGPL-3.0-or-later

import { VerificationTokenItem, WhoisDomainRecord } from '../types';

interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohJsonResponse {
  Status?: number;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
}

const COMMON_DKIM_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  'k2',
  's1',
  's2',
  'dkim',
  'mail',
  'smtp',
  'mandrill',
  'amazonses',
  'protonmail',
] as const;

/**
 * Queries DNS-over-HTTPS (RFC 8484 JSON format) directly from the browser
 * using CORS-enabled public resolvers (Cloudflare with Google DNS fallback).
 */
export async function queryBrowserDoh(name: string, type: string, timeoutMs = 3500): Promise<DohJsonResponse> {
  const endpoints = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
  ];

  for (const url of endpoints) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(url, {
        headers: { Accept: 'application/dns-json' },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        const json = (await res.json()) as DohJsonResponse;
        if (json && typeof json.Status === 'number') {
          return json;
        }
      }
    } catch {
      // Try fallback DoH resolver
    }
  }

  return {};
}

/**
 * Converts RFC 1035 SOA RNAME (e.g., "dns-admin.cloudflare.com." or "first\.last.example.com.")
 * into standard email notation ("dns-admin@cloudflare.com").
 */
function parseSoaRname(rawRname: string): string {
  const trimmed = rawRname.replace(/\.$/, '').trim();
  if (!trimmed) return '';

  // Find first unescaped dot separating local-part from domain
  let splitIdx = -1;
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] === '.' && (i === 0 || trimmed[i - 1] !== '\\')) {
      splitIdx = i;
      break;
    }
  }

  if (splitIdx === -1) return trimmed.replace(/\\\./g, '.').toLowerCase();
  const local = trimmed.slice(0, splitIdx).replace(/\\\./g, '.').toLowerCase();
  const host = trimmed.slice(splitIdx + 1).replace(/\\\./g, '.').toLowerCase();
  return `${local}@${host}`;
}

/**
 * Parses RFC 1035 SOA record string returned by DoH JSON.
 */
function parseSoaRecord(data: string): {
  mname?: string;
  rname?: string;
  serial?: string;
} {
  const clean = data.trim();
  const parts = clean.split(/\s+/);
  if (parts.length < 2) {
    return {};
  }
  const mname = parts[0].replace(/\.$/, '').toLowerCase();
  const rname = parseSoaRname(parts[1]);
  const serial = parts[2] && /^\d+$/.test(parts[2]) ? parts[2] : undefined;
  return { mname, rname, serial };
}

/**
 * Converts an IPv4 address to its RFC 1035 in-addr.arpa reverse lookup name.
 */
function ipv4ToArpa(ip: string): string | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  if (parts.some((p) => !/^\d+$/.test(p) || Number(p) < 0 || Number(p) > 255)) {
    return null;
  }
  return `${parts.reverse().join('.')}.in-addr.arpa`;
}

/**
 * Converts an IPv6 address to its RFC 3596 ip6.arpa reverse lookup name.
 */
function ipv6ToArpa(ip: string): string | null {
  const clean = ip.trim().split('%')[0].toLowerCase();
  if (!clean.includes(':')) return null;

  const halves = clean.split('::');
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;

  const fullGroups = [
    ...left,
    ...Array.from({ length: missing }, () => '0000'),
    ...right,
  ].map((g) => g.padStart(4, '0'));

  if (fullGroups.length !== 8 || fullGroups.some((g) => !/^[0-9a-f]{4}$/.test(g))) {
    return null;
  }

  const nibbles = fullGroups.join('').split('').reverse().join('.');
  return `${nibbles}.ip6.arpa`;
}

/**
 * Parses RFC 8659 CAA record from textual DoH format or RFC 3597 hex wire format (\# len hex).
 */
function parseCaaData(raw: string): { formatted: string; iodef?: string } {
  const trimmed = raw.trim();

  // RFC 3597 hex wire format: "\# <byteLength> <hexBytes>"
  if (trimmed.startsWith('\\#')) {
    const tokens = trimmed.split(/\s+/);
    const hex = tokens.slice(2).join('').toLowerCase();
    if (/^[0-9a-f]+$/.test(hex) && hex.length >= 6) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
      }
      const flags = bytes[0];
      const tagLen = bytes[1];
      if (2 + tagLen <= bytes.length) {
        const decoder = new TextDecoder('utf-8', { fatal: false });
        const tag = decoder.decode(bytes.slice(2, 2 + tagLen)).toLowerCase();
        const value = decoder.decode(bytes.slice(2 + tagLen));
        const formatted = `${flags} ${tag} "${value}"`;
        return {
          formatted,
          iodef: tag === 'iodef' && value ? value.trim() : undefined,
        };
      }
    }
  }

  // Standard textual format: 0 issue "letsencrypt.org"
  const textMatch = trimmed.match(/^(\d+)\s+([a-z0-9-]+)\s+"?([^"]+)"?$/i);
  if (textMatch) {
    const flags = textMatch[1];
    const tag = textMatch[2].toLowerCase();
    const value = textMatch[3].trim();
    return {
      formatted: `${flags} ${tag} "${value}"`,
      iodef: tag === 'iodef' && value ? value : undefined,
    };
  }

  return { formatted: trimmed };
}

/**
 * Strips surrounding quotes from TXT record answers returned by DoH resolvers.
 */
function cleanTxtValue(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed
      .slice(1, -1)
      .replace(/"\s+"/g, '')
      .replace(/\\"/g, '"');
  }
  return trimmed;
}

/**
 * Parses TXT records for verification tokens and RFC 7208 SPF mechanisms (includes + IP leaks).
 */
function parseTxtAttribution(txtValues: string[]): {
  verificationTokens: VerificationTokenItem[];
  spfRecord?: string;
  spfIncludes: string[];
  spfIpMechanisms: string[];
} {
  const verificationTokens: VerificationTokenItem[] = [];
  let spfRecord: string | undefined;
  const spfIncludes: string[] = [];
  const spfIpMechanisms: string[] = [];

  for (const record of txtValues) {
    const lower = record.toLowerCase();

    if (lower.startsWith('v=spf1')) {
      spfRecord = record;
      const parts = record.split(/\s+/);
      for (const part of parts) {
        const pLower = part.toLowerCase();
        if (pLower.startsWith('include:')) {
          spfIncludes.push(part.slice(8));
        } else if (
          pLower.startsWith('ip4:') ||
          pLower.startsWith('ip6:') ||
          pLower.startsWith('a:') ||
          pLower.startsWith('mx:') ||
          pLower.startsWith('redirect=') ||
          pLower === 'a' ||
          pLower === 'mx'
        ) {
          spfIpMechanisms.push(part);
        }
      }
    }

    if (lower.startsWith('google-site-verification=')) {
      verificationTokens.push({
        provider: 'Google Workspace / Cloud',
        token: record.split('=')[1] || '',
        raw: record,
      });
    } else if (lower.startsWith('ms=') || lower.startsWith('ms-')) {
      verificationTokens.push({
        provider: 'Microsoft 365 / Azure',
        token: record.replace(/^ms[-=]/i, ''),
        raw: record,
      });
    } else if (lower.startsWith('atlassian-domain-verification=')) {
      verificationTokens.push({
        provider: 'Atlassian Cloud',
        token: record.split('=')[1] || '',
        raw: record,
      });
    } else if (lower.startsWith('apple-domain-verification=')) {
      verificationTokens.push({
        provider: 'Apple Business',
        token: record.split('=')[1] || '',
        raw: record,
      });
    } else if (lower.startsWith('facebook-domain-verification=')) {
      verificationTokens.push({
        provider: 'Meta / Facebook Business',
        token: record.split('=')[1] || '',
        raw: record,
      });
    } else if (lower.startsWith('stripe-verification=')) {
      verificationTokens.push({
        provider: 'Stripe Payments',
        token: record.split('=')[1] || '',
        raw: record,
      });
    } else if (lower.startsWith('adobe-idp-site-verification=')) {
      verificationTokens.push({
        provider: 'Adobe Identity Federation',
        token: record.split('=')[1] || '',
        raw: record,
      });
    } else if (lower.includes('verification=') || lower.includes('site-verification=')) {
      const parts = record.split('=');
      verificationTokens.push({
        provider: parts[0] || 'Verification Token',
        token: parts.slice(1).join('='),
        raw: record,
      });
    }
  }

  return {
    verificationTokens,
    spfRecord,
    spfIncludes: Array.from(new Set(spfIncludes)),
    spfIpMechanisms: Array.from(new Set(spfIpMechanisms)),
  };
}

/**
 * Enriches a WhoisDomainRecord in pure browser JavaScript using RFC 8484 DoH lookups:
 * SOA (MNAME/RNAME), PTR (reverse DNS), CAA/iodef, DS/DNSKEY, SPF IP mechanisms,
 * DMARC rua/ruf, and DKIM selectors + CNAME delegations.
 */
export async function enrichDomainWithBrowserDns(record: WhoisDomainRecord): Promise<WhoisDomainRecord> {
  const domain = record.domainName;
  const rootDomain = record.rootDomain || domain;

  // Prepare reverse DNS targets from resolved A and AAAA records
  const arpaTargets: Array<{ ip: string; arpa: string }> = [];
  for (const ip of (record.aRecords || []).slice(0, 4)) {
    const arpa = ipv4ToArpa(ip);
    if (arpa) arpaTargets.push({ ip, arpa });
  }
  for (const ip of (record.aaaaRecords || []).slice(0, 2)) {
    const arpa = ipv6ToArpa(ip);
    if (arpa) arpaTargets.push({ ip, arpa });
  }

  // Run all DoH enrichment queries concurrently
  const [
    soaRes,
    rootSoaRes,
    caaRes,
    dsRes,
    dnskeyRes,
    txtRes,
    dmarcRes,
    ptrResults,
    dkimResults,
  ] = await Promise.all([
    queryBrowserDoh(domain, 'SOA'),
    rootDomain !== domain ? queryBrowserDoh(rootDomain, 'SOA') : Promise.resolve({} as DohJsonResponse),
    queryBrowserDoh(rootDomain, 'CAA'),
    queryBrowserDoh(rootDomain, 'DS'),
    queryBrowserDoh(rootDomain, 'DNSKEY'),
    queryBrowserDoh(rootDomain, 'TXT'),
    queryBrowserDoh(`_dmarc.${rootDomain}`, 'TXT'),
    Promise.all(
      arpaTargets.map(async (item) => {
        const res = await queryBrowserDoh(item.arpa, 'PTR');
        return { ip: item.ip, answers: res.Answer || [] };
      })
    ),
    Promise.all(
      COMMON_DKIM_SELECTORS.map(async (selector) => {
        const fqdn = `${selector}._domainkey.${rootDomain}`;
        const res = await queryBrowserDoh(fqdn, 'TXT', 2800);
        return { selector, answers: res.Answer || [] };
      })
    ),
  ]);

  // 1. SOA (MNAME, RNAME, Serial)
  const soaAnswers = [
    ...(soaRes.Answer || []).filter((a) => a.type === 6),
    ...(soaRes.Authority || []).filter((a) => a.type === 6),
    ...(rootSoaRes.Answer || []).filter((a) => a.type === 6),
    ...(rootSoaRes.Authority || []).filter((a) => a.type === 6),
  ];
  let soaMname = record.soaMname;
  let soaRname = record.soaRname;
  let soaSerial = record.soaSerial;

  if (soaAnswers.length > 0 && soaAnswers[0].data) {
    const parsedSoa = parseSoaRecord(soaAnswers[0].data);
    soaMname = parsedSoa.mname;
    soaRname = parsedSoa.rname;
    soaSerial = parsedSoa.serial;
  }

  // 2. PTR Reverse DNS
  const ptrRecords: string[] = [];
  const ptrHostnames: string[] = [];
  for (const item of ptrResults) {
    const ptrs = item.answers
      .filter((a) => a.type === 12)
      .map((a) => a.data.replace(/\.$/, '').toLowerCase())
      .filter(Boolean);
    for (const host of ptrs) {
      ptrRecords.push(`${item.ip} -> ${host}`);
      if (!ptrHostnames.includes(host)) {
        ptrHostnames.push(host);
      }
    }
  }

  // 3. CAA (RFC 8659)
  const caaRecords: string[] = [];
  const caaIodef: string[] = [];
  for (const ans of caaRes.Answer || []) {
    if (ans.type === 257 && ans.data) {
      const parsed = parseCaaData(ans.data);
      if (!caaRecords.includes(parsed.formatted)) {
        caaRecords.push(parsed.formatted);
      }
      if (parsed.iodef && !caaIodef.includes(parsed.iodef)) {
        caaIodef.push(parsed.iodef);
      }
    }
  }

  // 4. DNSSEC DS & DNSKEY (RFC 4034)
  const dsRecords: string[] = [];
  for (const ans of dsRes.Answer || []) {
    if (ans.type === 43 && ans.data) {
      const parts = ans.data.trim().split(/\s+/);
      if (parts.length >= 4) {
        const digestShort = parts[3].slice(0, 16);
        dsRecords.push(`Tag ${parts[0]} · Alg ${parts[1]} · Type ${parts[2]} · ${digestShort}...`);
      } else {
        dsRecords.push(ans.data.trim());
      }
    }
  }

  const dnskeyRecords: string[] = [];
  for (const ans of dnskeyRes.Answer || []) {
    if (ans.type === 48 && ans.data) {
      const parts = ans.data.trim().split(/\s+/);
      if (parts.length >= 4) {
        const flags = parts[0];
        const role = flags === '257' ? 'KSK' : flags === '256' ? 'ZSK' : 'KEY';
        const keyShort = parts.slice(3).join('').slice(0, 16);
        dnskeyRecords.push(`${role} (${flags}) · Alg ${parts[2]} · ${keyShort}...`);
      } else {
        dnskeyRecords.push(ans.data.trim());
      }
    }
  }

  // 5. TXT Attribution & SPF IP mechanisms
  const txtValues = (txtRes.Answer || [])
    .filter((a) => a.type === 16 && a.data)
    .map((a) => cleanTxtValue(a.data));
  const txtAttr = parseTxtAttribution(txtValues);

  const mergedTokens =
    record.verificationTokens && record.verificationTokens.length > 0
      ? record.verificationTokens
      : txtAttr.verificationTokens;
  const spfRecord = record.spfRecord || txtAttr.spfRecord;
  const spfIncludes =
    record.spfIncludes && record.spfIncludes.length > 0
      ? record.spfIncludes
      : txtAttr.spfIncludes;
  const spfIpMechanisms = txtAttr.spfIpMechanisms;

  // 6. DMARC (p=, rua=, ruf=)
  let dmarcPolicy = record.dmarcPolicy;
  let dmarcRua = record.dmarcRua;
  let dmarcRuf = record.dmarcRuf;
  const dmarcTexts = (dmarcRes.Answer || [])
    .filter((a) => a.type === 16 && a.data)
    .map((a) => cleanTxtValue(a.data))
    .filter((t) => t.toLowerCase().includes('v=dmarc1'));

  if (dmarcTexts.length > 0) {
    const rawDmarc = dmarcTexts[0];
    if (!dmarcPolicy) {
      const pMatch = rawDmarc.match(/(?:^|[;\s])p=([a-z]+)/i);
      if (pMatch) dmarcPolicy = pMatch[1].toLowerCase();
    }
    if (!dmarcRua) {
      const ruaMatch = rawDmarc.match(/(?:^|[;\s])rua=([^;]+)/i);
      if (ruaMatch) dmarcRua = ruaMatch[1].trim();
    }
    const rufMatch = rawDmarc.match(/(?:^|[;\s])ruf=([^;]+)/i);
    if (rufMatch) dmarcRuf = rufMatch[1].trim();
  }

  // 7. DKIM Selectors & CNAME Tenant Delegations
  const dkimSelectors: string[] = [];
  const dkimCnames: string[] = [];

  for (const item of dkimResults) {
    const cnameAns = item.answers.find((a) => a.type === 5 && a.data);
    const txtAns = item.answers.find((a) => a.type === 16 && a.data);

    if (cnameAns) {
      const target = cnameAns.data.replace(/\.$/, '').toLowerCase();
      if (!dkimCnames.includes(target)) {
        dkimCnames.push(target);
      }
      dkimSelectors.push(`${item.selector}: CNAME -> ${target}`);
    } else if (txtAns) {
      const cleaned = cleanTxtValue(txtAns.data);
      const lower = cleaned.toLowerCase();
      if (lower.includes('v=dkim1') || lower.includes('p=')) {
        const kMatch = cleaned.match(/(?:^|[;\s])k=([a-z0-9]+)/i);
        const pMatch = cleaned.match(/(?:^|[;\s])p=([A-Za-z0-9+/=]+)/);
        const keyAlg = kMatch ? `k=${kMatch[1]}` : 'k=rsa';
        const keyPreview = pMatch
          ? pMatch[1]
            ? `p=${pMatch[1].slice(0, 18)}...`
            : 'p=(revoked)'
          : cleaned.slice(0, 32);
        dkimSelectors.push(`${item.selector}: ${keyAlg} · ${keyPreview}`);
      }
    }
  }

  return {
    ...record,
    soaMname,
    soaRname,
    soaSerial,
    ptrRecords,
    ptrHostnames,
    caaRecords,
    caaIodef,
    dsRecords,
    dnskeyRecords,
    verificationTokens: mergedTokens,
    spfRecord,
    spfIncludes,
    spfIpMechanisms,
    dmarcPolicy,
    dmarcRua,
    dmarcRuf,
    dkimSelectors,
    dkimCnames,
  };
}
