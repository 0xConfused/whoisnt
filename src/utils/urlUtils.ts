// SPDX-License-Identifier: AGPL-3.0-or-later

const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'ed.jp',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.mx', 'org.mx', 'edu.mx', 'gob.mx', 'net.mx',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'nic.in', 'ac.in', 'edu.in', 'gov.in',
  'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg',
  'co.za', 'net.za', 'org.za', 'web.za', 'gov.za',
  'com.tr', 'net.tr', 'org.tr', 'edu.tr', 'gov.tr',
  'com.hk', 'org.hk', 'net.hk', 'edu.hk', 'gov.hk',
  'com.tw', 'org.tw', 'net.tw', 'edu.tw', 'gov.tw',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'gc.ca', 'qc.ca', 'ab.ca', 'bc.ca', 'on.ca',
  'co.kr', 'or.kr', 'ne.kr', 're.kr', 'pe.kr', 'go.kr',
  'co.id', 'or.id', 'ac.id', 'go.id', 'web.id', 'sch.id',
  'co.il', 'org.il', 'ac.il', 'gov.il', 'net.il',
  'com.ar', 'net.ar', 'org.ar', 'gov.ar', 'gob.ar',
  'com.co', 'org.co', 'gov.co', 'edu.co', 'net.co',
  'com.pe', 'org.pe', 'gob.pe', 'edu.pe', 'net.pe',
  'com.ua', 'org.ua', 'net.ua', 'gov.ua', 'edu.ua',
  'co.th', 'in.th', 'ac.th', 'go.th', 'or.th',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  'com.ph', 'org.ph', 'gov.ph', 'edu.ph', 'net.ph',
  'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
  'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
  'com.ng', 'org.ng', 'gov.ng', 'edu.ng', 'net.ng',
  'co.ke', 'or.ke', 'go.ke', 'ac.ke',
  'eu.org',
]);

const CONTROL_OR_BIDI_RE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/;

const RESERVED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
  'metadata.google.internal',
  'instance-data',
]);

const RESERVED_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.lan',
  '.home',
  '.corp',
  '.invalid',
  '.test',
  '.example',
  '.arpa',
];

export function sanitizeDomainInput(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 512) return '';
  // Reject inputs containing embedded control, newline, tab, zero-width, or bidi-override characters
  if (CONTROL_OR_BIDI_RE.test(trimmed)) return '';

  let str = trimmed;
  try {
    str = str.normalize('NFC');
  } catch {
    return '';
  }

  // Only strip explicit http:// or https:// protocols; preserve other schemes so validation rejects them
  str = str.replace(/^https?:\/\//i, '');
  // Isolate authority from path, query, and fragment (preserve backslashes and '@' so malformed inputs fail validation)
  str = str.split('/')[0].split('?')[0].split('#')[0];

  if (!str.includes('@')) {
    str = str.replace(/:\d+$/, '');
  }

  str = str.replace(/^\.+|\.+$/g, '').toLowerCase();
  if (!str || str.length > 253) return '';

  // Validate full hostname before stripping subdomains so malformed prefixes (e.g. foo@bar.example.com) are not masked
  if (!isValidDomainFormat(str)) {
    return str;
  }

  return extractApexDomain(str);
}

export function isValidDomainFormat(domain: string): boolean {
  if (typeof domain !== 'string' || !domain || domain.length < 3 || domain.length > 253) return false;
  if (!domain.includes('.')) return false;
  if (CONTROL_OR_BIDI_RE.test(domain)) return false;

  const lower = domain.toLowerCase();
  if (RESERVED_HOSTNAMES.has(lower)) return false;
  if (RESERVED_SUFFIXES.some((suffix) => lower.endsWith(suffix))) return false;

  // Strict RFC 1035 / RFC 1123 hostname syntax (ASCII letters, digits, hyphens only)
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9]{2,59})$/;
  return domainRegex.test(lower);
}

export function extractApexDomain(hostname: string): string {
  if (!hostname) return '';
  const clean = hostname.toLowerCase().trim().replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(':')) {
    return clean;
  }

  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;

  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

const HIGH_SIGNAL_WEB_PREFIXES = new Set([
  'www', 'app', 'web', 'portal', 'docs', 'doc', 'developer', 'developers', 'dev',
  'blog', 'news', 'shop', 'store', 'support', 'help', 'status', 'about', 'mail',
  'webmail', 'auth', 'login', 'sso', 'accounts', 'account', 'api', 'cdn',
  'dashboard', 'admin', 'forum', 'community', 'careers', 'jobs', 'pay', 'billing',
  'm', 'mobile', 'en', 'us',
]);

const FALLBACK_COMMON_PREFIXES = [
  'www', 'app', 'api', 'blog', 'docs', 'shop', 'support', 'status', 'mail', 'portal',
];

export function prioritizeSubdomainsForRecon(
  rootDomain: string,
  discovered: string[],
  maxCount = 24
): string[] {
  const apex = (extractApexDomain(rootDomain) || rootDomain).toLowerCase().trim();
  if (!apex || !isValidDomainFormat(apex)) return [];

  const seen = new Set<string>();
  const validSubs: string[] = [];

  const tryCollect = (rawHost: string) => {
    const h = String(rawHost || '').toLowerCase().trim().replace(/^\.+|\.+$/g, '');
    if (!h || h.includes('*')) return;
    if (h !== apex && !h.endsWith(`.${apex}`)) return;
    if (!isValidDomainFormat(h)) return;
    if (seen.has(h)) return;
    seen.add(h);
    validSubs.push(h);
  };

  tryCollect(apex);
  tryCollect(`www.${apex}`);

  for (const item of discovered) {
    tryCollect(item);
  }

  // If discovery returned no subdomains besides apex/www, seed common standard subdomains
  if (validSubs.length <= 2) {
    for (const prefix of FALLBACK_COMMON_PREFIXES) {
      tryCollect(`${prefix}.${apex}`);
    }
  }

  const scoreHost = (host: string): number => {
    if (host === apex) return 0;
    if (host === `www.${apex}`) return 1;
    const rel = host.slice(0, -(apex.length + 1));
    const labels = rel.split('.');
    const firstLabel = labels[0] || '';
    const depth = labels.length;
    if (depth === 1 && HIGH_SIGNAL_WEB_PREFIXES.has(firstLabel)) return 2;
    if (HIGH_SIGNAL_WEB_PREFIXES.has(firstLabel)) return 3;
    if (depth === 1) return 4;
    return 5 + depth;
  };

  const sorted = [...validSubs].sort((a, b) => {
    const sa = scoreHost(a);
    const sb = scoreHost(b);
    if (sa !== sb) return sa - sb;
    if (a.length !== b.length) return a.length - b.length;
    return a.localeCompare(b);
  });

  return sorted.slice(0, Math.max(1, maxCount));
}
