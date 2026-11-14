// SPDX-License-Identifier: AGPL-3.0-or-later

import express from 'express';
import path from 'path';
import tls from 'tls';
import dns from 'dns/promises';
import net from 'net';
import { createServer as createViteServer } from 'vite';
import { canonicalizeJsonStringify } from './src/utils/jsonSort';
import { parseFlexibleDateMs } from './src/utils/dateUtils';

const app = express();
const PORT = 3000;

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => {
  if (req.url && req.url.length > 4096) {
    return res.status(414).json({ error: 'Request URI exceeds safe maximum length limit (4096 bytes).' });
  }
  next();
});

app.use(express.json({ limit: '256kb' }));

function safeClampText(input: unknown, maxLen = 200): string {
  if (typeof input !== 'string') {
    if (typeof input === 'number' || typeof input === 'boolean') {
      return String(input);
    }
    return '';
  }

  let str = input;
  try {
    str = str.normalize('NFC');
  } catch {
    // Malformed sequence fallback
  }

  const codePoints = Array.from(str);
  if (codePoints.length > maxLen) {
    str = codePoints.slice(0, maxLen).join('');
  }

  if (Buffer.byteLength(str, 'utf8') > maxLen * 4) {
    const buf = Buffer.from(str, 'utf8').subarray(0, maxLen * 4);
    str = buf.toString('utf8');
  }

  return str;
}

function deepClampInputs(obj: unknown, maxLen = 200, depth = 0): unknown {
  if (depth > 5 || !obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      if (typeof obj[i] === 'string') {
        obj[i] = safeClampText(obj[i], maxLen);
      } else if (typeof obj[i] === 'object' && obj[i] !== null) {
        deepClampInputs(obj[i], maxLen, depth + 1);
      }
    }
  } else {
    const record = obj as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
      const val = record[key];
      if (typeof val === 'string') {
        record[key] = safeClampText(val, maxLen);
      } else if (typeof val === 'object' && val !== null) {
        deepClampInputs(val, maxLen, depth + 1);
      }
    }
  }
  return obj;
}

app.use((req, _res, next) => {
  if (req.query) {
    deepClampInputs(req.query, 200);
  }
  if (req.body && typeof req.body === 'object') {
    deepClampInputs(req.body, 200);
  }
  next();
});

function isPrivateOrLocalHost(hostname: string): boolean {
  if (!hostname) return true;
  let host = hostname.toLowerCase().trim();

  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1).trim();
  }

  if (host.includes(':')) {
    const colonCount = (host.match(/:/g) || []).length;
    if (colonCount === 1) {
      host = host.split(':')[0];
    }
  }

  if (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '0.0.0.0' ||
    host === '::1' ||
    host === '::' ||
    host === '0' ||
    host === 'metadata.google.internal' ||
    host === 'instance-data'
  ) {
    return true;
  }

  if (
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.lan') ||
    host.endsWith('.home') ||
    host.endsWith('.corp') ||
    host.endsWith('.invalid') ||
    host.endsWith('.test') ||
    host.endsWith('.example')
  ) {
    return true;
  }

  if (/^(\d+|0x[0-9a-f]+)$/i.test(host)) {
    const num = host.startsWith('0x') || host.startsWith('0X') ? parseInt(host, 16) : parseInt(host, 10);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const b1 = (num >>> 24) & 255;
      const b2 = (num >>> 16) & 255;
      const b3 = (num >>> 8) & 255;
      const b4 = num & 255;
      host = `${b1}.${b2}.${b3}.${b4}`;
    }
  }

  if (/^127\./.test(host)) return true; 
  if (/^10\./.test(host)) return true; 
  if (/^192\.168\./.test(host)) return true; 
  if (/^169\.254\./.test(host)) return true; 
  if (/^0\./.test(host)) return true; 
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(host)) return true; 

  const match172 = host.match(/^172\.(\d+)\./);
  if (match172) {
    const secondOctet = parseInt(match172[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }

  const firstOctetMatch = host.match(/^(\d+)\./);
  if (firstOctetMatch) {
    const firstOctet = parseInt(firstOctetMatch[1], 10);
    if (firstOctet >= 224) return true;
  }

  const ipType = net.isIP(host);
  if (ipType === 6) {
    if (host === '::1' || host === '::') return true;
    if (host.startsWith('::ffff:')) {
      const mappedPart = host.slice(7);
      if (mappedPart.includes('.')) {
        return isPrivateOrLocalHost(mappedPart);
      }
    }
    if (/^f[cd][0-9a-f]{2}:/i.test(host) || /^f[cd]:/i.test(host)) return true;
    if (/^fe[89ab][0-9a-f]:/i.test(host) || /^fe[89ab]:/i.test(host)) return true;
  }

  return false;
}

interface SafeFetchOptions extends RequestInit {
  maxRedirects?: number;
  validateRedirect?: (url: URL) => boolean;
  userIdentifier?: string | express.Request;
}

function extractUserIdentifier(req?: express.Request): string {
  if (!req) return '127.0.0.1';

  if (req.ip) {
    const candidate = req.ip.replace(/^::ffff:/, '').trim();
    if (candidate) return candidate === '::1' ? '127.0.0.1' : candidate;
  }

  if (req.socket?.remoteAddress) {
    const candidate = req.socket.remoteAddress.replace(/^::ffff:/, '').trim();
    if (candidate) return candidate === '::1' ? '127.0.0.1' : candidate;
  }

  return '127.0.0.1';
}

function getUserAgent(reqOrIdentifier?: express.Request | string): string {
  let id = '127.0.0.1';
  if (typeof reqOrIdentifier === 'string' && reqOrIdentifier.trim()) {
    id = reqOrIdentifier.trim();
  } else if (reqOrIdentifier && typeof reqOrIdentifier === 'object') {
    id = extractUserIdentifier(reqOrIdentifier);
  }
  return `Mozilla/5.0 (compatible; 0xCONFUSED./whoisnt; user: ${id})`;
}

class CircularRedirectError extends Error {
  isCircularRedirect = true;
  redirectChain: string[];
  finalUrl: string;
  statusCode: number;

  constructor(chain: string[], finalUrl: string, statusCode = 310) {
    super(`Circular redirect loop detected: ${chain.join(' -> ')} -> ${finalUrl}`);
    this.name = 'CircularRedirectError';
    this.redirectChain = [...chain, finalUrl];
    this.finalUrl = finalUrl;
    this.statusCode = statusCode;
  }
}

function decodeUnreservedRfc3986(str: string): string {
  return str.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
    const code = parseInt(hex, 16);
    if (
      (code >= 48 && code <= 57) ||
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122) ||
      code === 45 ||
      code === 95 ||
      code === 46 ||
      code === 126
    ) {
      return String.fromCharCode(code);
    }
    return match;
  });
}

async function safeFetch(
  initialUrl: string,
  options: SafeFetchOptions = {}
): Promise<Response> {
  const maxRedirects = options.maxRedirects ?? 5;
  let currentUrl = initialUrl;
  let redirectsCount = 0;
  const redirectChain: string[] = [initialUrl];
  const seenHops = new Set<string>();
  seenHops.add(cleanUrl(initialUrl, undefined, false, true) || initialUrl);

  const { maxRedirects: _, validateRedirect, userIdentifier, ...fetchOpts } = options;

  const headers = new Headers(fetchOpts.headers || {});
  if (!headers.has('User-Agent') && !headers.has('user-agent')) {
    headers.set('User-Agent', getUserAgent(userIdentifier));
  }

  while (true) {
    let parsed: URL;
    try {
      parsed = new URL(currentUrl);
    } catch {
      throw new Error(`Invalid URL for safeFetch: ${currentUrl}`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Blocked non-HTTP(S) protocol: ${parsed.protocol}`);
    }

    if (isPrivateOrLocalHost(parsed.hostname)) {
      throw new Error(`SSRF blocked: Attempted request to private or local host (${parsed.hostname})`);
    }

    if (validateRedirect && !validateRedirect(parsed)) {
      throw new Error(`Redirect target disallowed by security policy: ${parsed.hostname}`);
    }

    const res = await fetch(currentUrl, {
      ...fetchOpts,
      headers,
      redirect: 'manual',
    });

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get('location');
      if (!location) {
        try {
          Object.defineProperty(res, 'url', { value: currentUrl, configurable: true });
          (res as any).redirectChain = redirectChain;
          (res as any).finalUrl = currentUrl;
        } catch {}
        return res;
      }

      let nextUrl: string;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        throw new Error(`Invalid redirect Location header received: ${location}`);
      }

      const nextParsed = new URL(nextUrl);

      if (nextParsed.protocol !== 'http:' && nextParsed.protocol !== 'https:') {
        throw new Error(`Blocked redirect to unsafe protocol: ${nextParsed.protocol}`);
      }

      if (isPrivateOrLocalHost(nextParsed.hostname)) {
        throw new Error(`SSRF blocked: Redirect target points to private or local host (${nextParsed.hostname})`);
      }

      const normalizedNext = cleanUrl(nextUrl, undefined, false, true) || nextUrl;
      // Fast loop breaker: abort immediately on circular redirect cycle
      if (seenHops.has(normalizedNext)) {
        throw new CircularRedirectError(redirectChain, nextUrl, res.status);
      }
      seenHops.add(normalizedNext);
      redirectChain.push(nextUrl);

      redirectsCount++;
      if (redirectsCount > maxRedirects) {
        throw new Error(`Too many redirects (exceeded limit of ${maxRedirects}): ${redirectChain.join(' -> ')}`);
      }

      if (validateRedirect && !validateRedirect(nextParsed)) {
        try {
          Object.defineProperty(res, 'url', { value: currentUrl, configurable: true });
          (res as any).redirectChain = redirectChain;
          (res as any).finalUrl = currentUrl;
        } catch {}
        return res;
      }

      currentUrl = nextUrl;

      if (res.status === 303 && fetchOpts.method && fetchOpts.method !== 'GET' && fetchOpts.method !== 'HEAD') {
        fetchOpts.method = 'GET';
        delete fetchOpts.body;
      }

      continue;
    }

    try {
      Object.defineProperty(res, 'url', { value: currentUrl, configurable: true });
      (res as any).redirectChain = redirectChain;
      (res as any).finalUrl = currentUrl;
    } catch {}

    return res;
  }
}

function cleanUrl(rawUrl: string, _baseDomain?: string, stripQuery = true, stripHash = true): string | null {
  try {
    let urlStr = rawUrl.trim();
    if (!/^https?:\/\//i.test(urlStr)) {
      urlStr = 'https://' + urlStr;
    }
    const parsed = new URL(urlStr);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }

    // Default port stripping (:80 / :443)
    if (parsed.protocol === 'http:' && parsed.port === '80') {
      parsed.port = '';
    } else if (parsed.protocol === 'https:' && parsed.port === '443') {
      parsed.port = '';
    }

    if (stripHash) {
      parsed.hash = '';
    }

    if (stripQuery) {
      parsed.search = '';
    } else if (parsed.search) {
      // Parameter sorting: canonical parameter ordering
      parsed.searchParams.sort();
    }

    parsed.pathname = decodeUnreservedRfc3986(parsed.pathname).replace(/\/+/g, '/');
    if (parsed.pathname.length > 1 && parsed.pathname.endsWith('/')) {
      parsed.pathname = parsed.pathname.replace(/\/+$/, '');
    }

    return parsed.href;
  } catch {
    return null;
  }
}

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

async function fetchDnsOverHttps(domain: string, type: string, userAgentOrReq?: string | express.Request): Promise<any[]> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`, {
      headers: {
        Accept: 'application/dns-json',
        'User-Agent': getUserAgent(userAgentOrReq),
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data = await res.json();
    return data.Answer || [];
  } catch {
    return [];
  }
}

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
]);

function extractApexDomain(hostname: string): string {
  const clean = hostname.toLowerCase().trim().replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;

  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

let ianaBootstrapCache: any = null;
let ianaBootstrapFetchedAt = 0;

async function getIanaBootstrap(userAgentOrReq?: string | express.Request): Promise<any> {
  const now = Date.now();
  if (ianaBootstrapCache && now - ianaBootstrapFetchedAt < 24 * 60 * 60 * 1000) {
    return ianaBootstrapCache;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch('https://data.iana.org/rdap/dns.json', {
      signal: controller.signal,
      headers: {
        'User-Agent': getUserAgent(userAgentOrReq),
        Accept: 'application/json',
      },
    });
    clearTimeout(timeout);
    if (res.ok) {
      ianaBootstrapCache = await res.json();
      ianaBootstrapFetchedAt = now;
    }
  } catch {}
  return ianaBootstrapCache;
}

async function getAuthoritativeRdapUrl(domain: string, userAgentOrReq?: string | express.Request): Promise<string | null> {
  const parts = domain.split('.');
  const tld = parts[parts.length - 1].toLowerCase();
  const bootstrap = await getIanaBootstrap(userAgentOrReq);

  if (bootstrap && Array.isArray(bootstrap.services)) {
    for (const service of bootstrap.services) {
      const tlds = service[0];
      const urls = service[1];
      if (Array.isArray(tlds) && tlds.includes(tld) && Array.isArray(urls) && urls.length > 0) {
        const base = urls[0].endsWith('/') ? urls[0] : urls[0] + '/';
        return `${base}domain/${encodeURIComponent(domain)}`;
      }
    }
  }

  const staticMap: Record<string, string> = {
    com: 'https://rdap.verisign.com/com/v1/domain/',
    net: 'https://rdap.verisign.com/net/v1/domain/',
    org: 'https://rdap.publicinterestregistry.org/rdap/domain/',
    info: 'https://rdap.identitydigital.services/rdap/domain/',
    biz: 'https://rdap.identitydigital.services/rdap/domain/',
    mobi: 'https://rdap.identitydigital.services/rdap/domain/',
    app: 'https://rdap.nic.google/domain/',
    dev: 'https://rdap.nic.google/domain/',
    page: 'https://rdap.nic.google/domain/',
    fr: 'https://rdap.nic.fr/domain/',
    uk: 'https://rdap.nominet.uk/uk/domain/',
    ca: 'https://rdap.ca.fury.ca/rdap/domain/',
    nl: 'https://rdap.sidn.nl/domain/',
    de: 'https://rdap.denic.de/domain/',
    cz: 'https://rdap.nic.cz/domain/',
    se: 'https://rdap.iis.se/domain/',
    nu: 'https://rdap.iis.se/domain/',
    br: 'https://rdap.registro.br/domain/',
  };

  if (staticMap[tld]) {
    return `${staticMap[tld]}${encodeURIComponent(domain)}`;
  }
  return null;
}

function readVcardScalar(val: unknown): string {
  if (typeof val === 'string') return val.trim();
  if (Array.isArray(val)) return val.map((x) => (typeof x === 'string' ? x.trim() : '')).filter(Boolean).join(' ');
  return '';
}

function parseRdapData(rdapData: any, domain: string, rootDomain: string) {
  let registrarName = '';
  let ianaId = '';
  let abuseContact = '';
  let registrantOrg = '';
  let registrantCountry = '';
  let registrantState = '';
  let registrantCity = '';

  const searchEntities = (entities: any[]) => {
    if (!Array.isArray(entities)) return;
    for (const ent of entities) {
      const roles = Array.isArray(ent.roles) ? ent.roles.map((r: any) => String(r).toLowerCase()) : [];
      const vcardProps = Array.isArray(ent.vcardArray) && Array.isArray(ent.vcardArray[1]) ? ent.vcardArray[1] : null;

      if (roles.includes('registrar') || roles.includes('sponsor')) {
        if (vcardProps) {
          const fnItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'fn');
          const fnVal = fnItem ? readVcardScalar(fnItem[3]) : '';
          if (fnVal) registrarName = fnVal;
          const orgItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'org');
          const orgVal = orgItem ? readVcardScalar(orgItem[3]) : '';
          if (!registrarName && orgVal) registrarName = orgVal;
        }
        if (!registrarName && ent.handle) registrarName = String(ent.handle);
        if (Array.isArray(ent.publicIds)) {
          const ianaPublicId = ent.publicIds.find(
            (p: any) => p && typeof p.type === 'string' && p.type.toLowerCase().includes('iana')
          );
          if (ianaPublicId && ianaPublicId.identifier !== undefined) {
            ianaId = String(ianaPublicId.identifier);
          }
        }
      }
      if (roles.includes('abuse')) {
        if (vcardProps) {
          const emailItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'email');
          const emailVal = emailItem ? readVcardScalar(emailItem[3]).replace(/^mailto:/i, '') : '';
          if (emailVal) abuseContact = emailVal;
          const telItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'tel');
          const telVal = telItem ? readVcardScalar(telItem[3]).replace(/^tel:/i, '') : '';
          if (!abuseContact && telVal) abuseContact = telVal;
        }
      }
      if (roles.includes('registrant')) {
        if (vcardProps) {
          const orgItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'org');
          const orgVal = orgItem ? readVcardScalar(orgItem[3]) : '';
          if (orgVal) registrantOrg = orgVal;
          const fnItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'fn');
          const fnVal = fnItem ? readVcardScalar(fnItem[3]) : '';
          if (!registrantOrg && fnVal && !/redacted|privacy|not disclosed/i.test(fnVal)) {
            registrantOrg = fnVal;
          }
          const adrItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'adr');
          if (adrItem && Array.isArray(adrItem[3])) {
            if (adrItem[3][4]) registrantCity = readVcardScalar(adrItem[3][4]) || String(adrItem[3][3] || '');
            if (adrItem[3][5]) registrantState = String(adrItem[3][5]);
            if (adrItem[3][6]) registrantCountry = String(adrItem[3][6]);
          }
          if (!registrantCountry && adrItem && adrItem[1] && typeof adrItem[1].cc === 'string') {
            registrantCountry = adrItem[1].cc;
          }
        }
      }
      if (ent.entities) searchEntities(ent.entities);
    }
  };

  if (rdapData.entities) {
    searchEntities(rdapData.entities);
  }

  if (!registrantOrg && Array.isArray(rdapData.auData_eligibility)) {
    const regEntry = rdapData.auData_eligibility.find(
      (item: any) => item && typeof item.name === 'string' && item.name.toLowerCase() === 'registrant name' && item.value
    );
    if (regEntry) {
      registrantOrg = String(regEntry.value).trim();
    }
  }

  let createdDate = '';
  let updatedDate = '';
  let expiresDate = '';

  if (rdapData.events && Array.isArray(rdapData.events)) {
    for (const ev of rdapData.events) {
      const action = String(ev?.eventAction || '').toLowerCase();
      if (action === 'registration' || action === 'created') createdDate = ev.eventDate;
      if (action === 'last changed' || action === 'last update') updatedDate = ev.eventDate;
      if (action === 'expiration' || action === 'expiry') expiresDate = ev.eventDate;
    }
  }

  const nameservers: string[] = Array.from(
    new Set(
      (Array.isArray(rdapData.nameservers) ? rdapData.nameservers : [])
        .map((ns: any) => (typeof ns === 'string' ? ns : ns?.ldhName || ns?.unicodeName || ns?.handle))
        .filter((v: unknown): v is string => typeof v === 'string' && v.trim().length > 0)
        .map((v: string) => v.trim().replace(/\.$/, '').toLowerCase())
    )
  );

  const status: string[] = Array.from(
    new Set(
      (Array.isArray(rdapData.status) ? rdapData.status : [])
        .filter((s: unknown): s is string => typeof s === 'string' && s.trim().length > 0)
        .map((s: string) => s.trim())
    )
  );

  return {
    domainName: rdapData.ldhName || rdapData.unicodeName || rootDomain || domain,
    rootDomain,
    queryDomain: domain,
    registrar: registrarName || rdapData.port43 || 'Unknown / Protected',
    ianaId: ianaId || undefined,
    createdDate: createdDate || undefined,
    updatedDate: updatedDate || undefined,
    expiresDate: expiresDate || undefined,
    status,
    nameservers,
    whoisServer: rdapData.port43 || undefined,
    abuseContact: abuseContact || undefined,
    registrantOrg: registrantOrg || undefined,
    registrantCountry: registrantCountry || undefined,
    registrantState: registrantState || undefined,
    registrantCity: registrantCity || undefined,
    source: 'rdap' as const,
    rawText: canonicalizeJsonStringify(rdapData).slice(0, 50000),
  };
}

function formatWhoisQuery(query: string, server: string): string {
  const clean = query.trim();
  const host = server.toLowerCase();
  if (host === 'whois.denic.de') return `-T dn,ace ${clean}`;
  if (host === 'whois.jprs.jp') return `${clean}/e`;
  return clean;
}

function tcpWhois(query: string, server = 'whois.iana.org', timeoutMs = 3500): Promise<string> {
  if (!server || isPrivateOrLocalHost(server)) {
    return Promise.resolve('');
  }
  return new Promise((resolve) => {
    let resolved = false;
    const socket = net.createConnection(43, server, () => {
      socket.write(formatWhoisQuery(query, server) + '\r\n');
    });
    let data = '';
    socket.on('data', (chunk) => (data += chunk));
    socket.on('end', () => {
      if (!resolved) {
        resolved = true;
        resolve(data);
      }
    });
    socket.on('error', () => {
      if (!resolved) {
        resolved = true;
        resolve(data);
      }
    });
    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        try {
          socket.destroy();
        } catch {}
        resolve(data);
      }
    }, timeoutMs);
  });
}

function parseWhoisText(rawText: string, domain: string, rootDomain: string) {
  if (!rawText || rawText.trim().length === 0) return null;

  const lines = rawText.split(/\r?\n/);

  const findMatch = (regex: RegExp) => {
    const m = rawText.match(regex);
    return m && m[1] ? m[1].trim() : undefined;
  };

  // Scan indented continuation lines after a section header (e.g. Nominet "Name servers:", Educause "Name Servers:")
  const findIndentedBlock = (headerRegex: RegExp): string[] => {
    const collected: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(headerRegex);
      if (!m) continue;
      if (m[1] && m[1].trim()) {
        collected.push(m[1].trim());
        continue;
      }
      for (let j = i + 1; j < lines.length; j++) {
        const nextLine = lines[j];
        if (!nextLine.trim()) break;
        if (!/^[ \t]+/.test(nextLine)) break;
        collected.push(nextLine.trim());
      }
    }
    return collected;
  };

  const domainName = findMatch(/^[ \t]*(?:[a-z]\.\s*)?(?:Domain Name|domain|\[Domain Name\]):?[^\S\r\n]+([^\r\n]+)/im) || rootDomain || domain;

  let registrar = findMatch(/^[ \t]*(?:Registrar Name|Sponsoring Registrar|Registrar|registrar-name):[^\S\r\n]+([^\r\n]+)/im);
  if (!registrar) {
    const nominetReg = findIndentedBlock(/^[ \t]*Registrar:[^\S\r\n]*([^\r\n]*)$/i);
    if (nominetReg.length > 0 && !/^(?:Registrar|URL)/i.test(nominetReg[0])) {
      registrar = nominetReg[0];
    }
  }
  if (!registrar && /EDUCAUSE Whois database is authoritative for the[\s\S]{0,40}\.EDU/i.test(rawText)) {
    registrar = 'EDUCAUSE';
  }

  const ianaId = findMatch(/^[ \t]*(?:Registrar IANA ID|IANA ID|Registrar IANA):[^\S\r\n]+([^\r\n]+)/im);

  const createdDate =
    findMatch(/^[ \t]*(?:Creation Date|Created On|Registration Date|Registered On|Registered on|Domain record activated|created|registered|\[Registered Date\]|\[Created on\]):?[^\S\r\n]+([^\r\n]+)/im) ||
    findMatch(/^[ \t]*\[Connected Date\][^\S\r\n]+([^\r\n]+)/im);

  const updatedDate =
    findMatch(/^[ \t]*(?:Updated Date|Last Updated On|Last Modified|Last updated|Domain record last updated|Modified|Changed|changed|last-update|modified|\[Last Update\]):?[^\S\r\n]+([^\r\n]+)/im);

  let expiresDate = findMatch(
    /^[ \t]*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry date|Expiry Date|Expires On|Domain expires|Expires|paid-till|expire|expires|\[Expires on\]):?[^\S\r\n]+([^\r\n]+)/im
  );
  if (!expiresDate) {
    const jprsStateExp = findMatch(/^[ \t]*\[State\][^\S\r\n]+Connected\s*\(([^)]+)\)/im);
    if (jprsStateExp) expiresDate = jprsStateExp;
  }

  const whoisServer = findMatch(/^[ \t]*(?:Registrar WHOIS Server|WHOIS Server|whois):[^\S\r\n]+([^\r\n]+)/im);
  const abuseContact = findMatch(/^[ \t]*(?:Registrar Abuse Contact Email|Abuse Contact Email|abuse-mailbox|Registrar Abuse Contact):[^\S\r\n]+([^\r\n]+)/im);
  const registrantCountry = findMatch(/^[ \t]*(?:Registrant Country|Country|registrant-country):[^\S\r\n]+([^\r\n]+)/im);
  const registrantOrg = findMatch(/^[ \t]*(?:Registrant Organization|g\.\s*\[Organization\]|organisation):?[^\S\r\n]+([^\r\n]+)/im);

  // Extract nameservers from single-line and multi-line indented blocks, stripping glue IPs
  const nsRawLines = [
    ...findIndentedBlock(/^(?:[a-z]\.\s*)?(?:Name Servers?|Nameservers|nserver|nameserver|\[Name Server\]):?[^\S\r\n]*([^\r\n]*)$/i),
  ];
  const nsSet = new Set<string>();
  for (const rawNs of nsRawLines) {
    if (/no nameservers listed/i.test(rawNs)) continue;
    const candidate = rawNs.trim().split(/\s+/)[0].replace(/\.$/, '').toLowerCase();
    if (/^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/.test(candidate)) {
      nsSet.add(candidate);
    }
  }
  const nameservers = Array.from(nsSet);

  // Extract EPP/registry status lines cleanly without trailing ICANN reference URLs
  const statusRawLines = findIndentedBlock(/^(?:[a-z]\.\s*)?(?:Domain Status|Registration status|Status|status|state|\[State\]):?[^\S\r\n]*([^\r\n]*)$/i);
  const statusSet = new Set<string>();
  for (const rawSt of statusRawLines) {
    let cleaned = rawSt
      .replace(/https?:\/\/\S+/gi, '')
      .replace(/\s*\(\d{4}[/-]\d{1,2}[/-]\d{1,2}\)\s*$/g, '')
      .trim()
      .toLowerCase();
    if (cleaned && !/^(?:unknown|none)$/i.test(cleaned)) {
      statusSet.add(cleaned);
    }
  }
  const status = Array.from(statusSet);

  return {
    domainName,
    rootDomain,
    queryDomain: domain,
    registrar: registrar || 'Protected / Not Disclosed',
    ianaId,
    createdDate,
    updatedDate,
    expiresDate,
    status,
    nameservers,
    whoisServer,
    abuseContact,
    registrantOrg,
    registrantCountry,
    rawText: rawText.slice(0, 15000),
    source: 'whois' as const,
  };
}

async function resolveDomainWhoisAndRdap(domain: string, userAgentOrReq?: string | express.Request) {
  const rootDomain = extractApexDomain(domain);
  const ua = getUserAgent(userAgentOrReq);

  const rdapUrl = await getAuthoritativeRdapUrl(rootDomain, ua);
  if (rdapUrl) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 6000);
      const res = await safeFetch(rdapUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': ua,
          Accept: 'application/rdap+json, application/json',
        },
        maxRedirects: 3,
      });
      clearTimeout(timeout);
      if (res.ok) {
        const rdapJson = await res.json();
        const parsed = parseRdapData(rdapJson, domain, rootDomain);
        if ((parsed.registrar && parsed.registrar !== 'Unknown / Protected') || parsed.createdDate || parsed.nameservers.length > 0) {
          return parsed;
        }
      }
    } catch {}
  }

  const tld = rootDomain.split('.').pop() || '';
  const candidateServers: string[] = [];

  if (tld === 'com' || tld === 'net') candidateServers.push('whois.verisign-grs.com');
  else if (tld === 'org') candidateServers.push('whois.publicinterestregistry.org');
  else if (tld === 'uk') candidateServers.push('whois.nic.uk');
  else if (tld === 'edu') candidateServers.push('whois.educause.edu');
  else if (tld === 'jp') candidateServers.push('whois.jprs.jp');
  else if (tld === 'nl') candidateServers.push('whois.sidn.nl');
  else if (tld === 'se') candidateServers.push('whois.iis.se');
  else if (tld === 'io') candidateServers.push('whois.nic.io');
  else if (tld === 'ai') candidateServers.push('whois.nic.ai');
  else if (tld === 'ca') candidateServers.push('whois.cira.ca');
  else if (tld === 'de') candidateServers.push('whois.denic.de');
  else if (tld === 'fr') candidateServers.push('whois.nic.fr');
  else if (tld === 'me') candidateServers.push('whois.nic.me');
  else if (tld === 'co') candidateServers.push('whois.nic.co');
  else if (tld === 'au') candidateServers.push('whois.auda.org.au');

  candidateServers.push(`whois.nic.${tld}`);
  candidateServers.push(`whois.${tld}`);
  candidateServers.push('whois.iana.org');

  const uniqueServers = Array.from(new Set(candidateServers));

  for (const server of uniqueServers) {
    try {
      const rawWhois = await tcpWhois(rootDomain, server, 3500);
      if (rawWhois && rawWhois.trim().length > 60) {
        const referral = rawWhois.match(/(?:Registrar WHOIS Server|refer):[^\S\r\n]+([^\r\n]+)/i)?.[1]?.trim();

        // Never parse IANA's TLD delegation block as domain WHOIS data; only follow its referral
        if (server === 'whois.iana.org') {
          if (referral && !referral.toLowerCase().includes('iana.org') && !referral.startsWith('http')) {
            try {
              const referredWhois = await tcpWhois(rootDomain, referral, 3500);
              if (referredWhois && referredWhois.trim().length > 60) {
                const parsed = parseWhoisText(referredWhois, domain, rootDomain);
                if (parsed && (parsed.registrar !== 'Protected / Not Disclosed' || parsed.createdDate || parsed.nameservers.length > 0)) {
                  return parsed;
                }
              }
            } catch {}
          }
          continue;
        }

        let combinedText = rawWhois;
        if (referral && !referral.toLowerCase().includes(server.toLowerCase()) && !referral.startsWith('http')) {
          try {
            const referredWhois = await tcpWhois(rootDomain, referral, 3500);
            if (referredWhois && referredWhois.trim().length > 60) {
              combinedText = referredWhois + '\n\n--- Registry WHOIS ---\n' + rawWhois;
            }
          } catch {}
        }

        const parsed = parseWhoisText(combinedText, domain, rootDomain);
        if (parsed && (parsed.registrar !== 'Protected / Not Disclosed' || parsed.createdDate || parsed.nameservers.length > 0)) {
          return parsed;
        }
      }
    } catch {}
  }

  try {
    const fallbackController = new AbortController();
    const fallbackTimeout = setTimeout(() => fallbackController.abort(), 3500);
    const fallbackRes = await safeFetch(`https://rdap-bootstrap.arin.net/bootstrap/domain/${encodeURIComponent(rootDomain)}`, {
      signal: fallbackController.signal,
      headers: {
        'User-Agent': ua,
        Accept: 'application/rdap+json, application/json',
      },
      maxRedirects: 3,
    });
    clearTimeout(fallbackTimeout);
    if (fallbackRes.ok) {
      const fallbackJson = await fallbackRes.json();
      return parseRdapData(fallbackJson, domain, rootDomain);
    }
  } catch {}

  return null;
}

const crtCache = new Map<string, { data: any; timestamp: number }>();

async function fetchCrtNameSubdomains(apexDomain: string, userAgentOrReq?: string | express.Request): Promise<any> {
  const cleanApex = apexDomain.toLowerCase().trim().replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');
  if (!cleanApex || isPrivateOrLocalHost(cleanApex)) {
    return {
      apexDomain: cleanApex,
      count: 0,
      subdomains: [],
      fetchedAt: Date.now(),
      sourceUrl: `https://crt.name/v1/search?apex=${encodeURIComponent(cleanApex)}`,
      error: 'Localhost or private networks are disallowed.',
    };
  }

  const cached = crtCache.get(cleanApex);
  if (cached && Date.now() - cached.timestamp < 10 * 60 * 1000) {
    return cached.data;
  }

  const sourceUrl = `https://crt.name/v1/search?apex=${encodeURIComponent(cleanApex)}`;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);
    const res = await safeFetch(sourceUrl, {
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': getUserAgent(userAgentOrReq),
      },
      maxRedirects: 3,
    });
    clearTimeout(timeout);

    if (!res.ok) {
      const errRes = {
        apexDomain: cleanApex,
        count: 0,
        subdomains: [],
        fetchedAt: Date.now(),
        sourceUrl,
        error: `crt.name service returned HTTP ${res.status}`,
      };
      crtCache.set(cleanApex, { data: errRes, timestamp: Date.now() });
      return errRes;
    }

    const text = await res.text();
    let subdomains: string[] = [];

    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) {
        subdomains = parsed
          .map((item: any) => (item.sub || item.name || (typeof item === 'string' ? item : '')).trim())
          .filter(Boolean);
      }
    } catch {
      subdomains = text.split('\n').map((l) => l.trim()).filter(Boolean);
    }

    const set = new Set<string>();
    for (const sub of subdomains) {
      const cleanSub = sub.toLowerCase().replace(/\s+/g, '').replace(/^\.+|\.+$/g, '');
      if (cleanSub) {
        set.add(cleanSub);
      }
    }

    const sortedSubdomains = Array.from(set).sort((a, b) => {
      if (a === cleanApex) return -1;
      if (b === cleanApex) return 1;
      const depthA = a.split('.').length;
      const depthB = b.split('.').length;
      if (depthA !== depthB) return depthA - depthB;
      return a.localeCompare(b);
    });

    const data = {
      apexDomain: cleanApex,
      count: sortedSubdomains.length,
      subdomains: sortedSubdomains,
      fetchedAt: Date.now(),
      sourceUrl,
    };

    crtCache.set(cleanApex, { data, timestamp: Date.now() });
    return data;
  } catch (err: any) {
    const errData = {
      apexDomain: cleanApex,
      count: 0,
      subdomains: [],
      fetchedAt: Date.now(),
      sourceUrl,
      error: err.message || 'Failed to connect to crt.name service',
    };
    return errData;
  }
}

async function lookupIpAsn(ip: string): Promise<{ asn?: string; asnName?: string; bgpPrefix?: string; subnet24?: string } | null> {
  if (!ip || !ip.includes('.')) return null;
  const octets = ip.split('.');
  if (octets.length !== 4) return null;
  const subnet24 = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;

  try {
    const rev = [...octets].reverse().join('.');
    const txts = await dns.resolveTxt(`${rev}.origin.asn.cymru.com`);
    if (!txts || txts.length === 0) return { subnet24 };
    const line = txts[0].join('');
    const parts = line.split('|').map((s) => s.trim());
    const rawAsn = parts[0] || '';
    const prefix = parts[1] || '';
    const asn = rawAsn ? `AS${rawAsn}` : undefined;

    let asnName: string | undefined;
    if (rawAsn) {
      try {
        const nameTxts = await dns.resolveTxt(`AS${rawAsn}.asn.cymru.com`);
        if (nameTxts && nameTxts.length > 0) {
          const nline = nameTxts[0].join('');
          const nparts = nline.split('|').map((s) => s.trim());
          asnName = nparts[nparts.length - 1] || undefined;
        }
      } catch {}
    }

    return {
      asn,
      asnName,
      bgpPrefix: prefix || undefined,
      subnet24,
    };
  } catch {
    return { subnet24 };
  }
}

async function inspectLiveTlsCert(hostname: string): Promise<{
  tlsSubjectCn?: string;
  tlsSubjectOrg?: string;
  tlsIssuerOrg?: string;
  tlsIssuerCn?: string;
  tlsProtocol?: string;
  tlsCipher?: string;
  tlsFingerprint256?: string;
  tlsSans?: string[];
}> {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = tls.connect(
      443,
      hostname,
      {
        servername: hostname,
        rejectUnauthorized: false,
      },
      () => {
        if (resolved) return;
        resolved = true;
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol() || undefined;
          const cipherInfo = socket.getCipher();
          const cipher = cipherInfo ? cipherInfo.name : undefined;

          let sans: string[] = [];
          if (cert && cert.subjectaltname) {
            sans = cert.subjectaltname
              .split(',')
              .map((s) => s.trim().replace(/^DNS:/i, ''))
              .filter(Boolean);
          }

          socket.destroy();
          resolve({
            tlsSubjectCn: (cert?.subject && (cert.subject as any).CN) || undefined,
            tlsSubjectOrg: (cert?.subject && (cert.subject as any).O) || undefined,
            tlsIssuerOrg: (cert?.issuer && (cert.issuer as any).O) || undefined,
            tlsIssuerCn: (cert?.issuer && (cert.issuer as any).CN) || undefined,
            tlsProtocol: protocol || undefined,
            tlsCipher: cipher || undefined,
            tlsFingerprint256: cert?.fingerprint256 || undefined,
            tlsSans: sans.slice(0, 30),
          });
        } catch {
          socket.destroy();
          resolve({});
        }
      }
    );

    socket.on('error', () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve({});
      }
    });

    socket.setTimeout(3500, () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve({});
      }
    });
  });
}

async function extractAttributionAndVerification(domain: string): Promise<{
  verificationTokens: Array<{ provider: string; token: string; raw: string }>;
  spfRecord?: string;
  spfIncludes: string[];
  dmarcPolicy?: string;
  dmarcRua?: string;
}> {
  const verificationTokens: Array<{ provider: string; token: string; raw: string }> = [];
  let spfRecord: string | undefined;
  const spfIncludes: string[] = [];
  let dmarcPolicy: string | undefined;
  let dmarcRua: string | undefined;

  try {
    const txtRecords = await dns.resolveTxt(domain);
    const flatTxt = txtRecords.map((chunks) => chunks.join(''));

    for (const record of flatTxt) {
      const lower = record.toLowerCase();

      // SPF
      if (lower.startsWith('v=spf1')) {
        spfRecord = record;
        const parts = record.split(/\s+/);
        for (const p of parts) {
          if (p.toLowerCase().startsWith('include:')) {
            spfIncludes.push(p.slice(8));
          }
        }
      }

      // Verification tokens
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
  } catch {}

  // DMARC
  try {
    const dmarcTxt = await dns.resolveTxt(`_dmarc.${domain}`);
    const flatDmarc = dmarcTxt.map((chunks) => chunks.join('')).join(' ');
    if (flatDmarc.toLowerCase().includes('v=dmarc1')) {
      const pMatch = flatDmarc.match(/p=([a-z]+)/i);
      if (pMatch) dmarcPolicy = pMatch[1].toLowerCase();
      const ruaMatch = flatDmarc.match(/rua=([^;]+)/i);
      if (ruaMatch) dmarcRua = ruaMatch[1].trim();
    }
  } catch {}

  return {
    verificationTokens,
    spfRecord,
    spfIncludes: Array.from(new Set(spfIncludes)),
    dmarcPolicy,
    dmarcRua,
  };
}

async function probeWebServer(domain: string, userAgent: string): Promise<{
  httpWebServer?: string;
  httpStatusCode?: number;
  hstsEnabled?: boolean;
  cspPresent?: boolean;
}> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);
    const res = await safeFetch(`https://${domain}`, {
      method: 'HEAD',
      headers: { 'User-Agent': userAgent },
      signal: controller.signal,
      maxRedirects: 3,
    });
    clearTimeout(timeout);

    const serverHeader = res.headers.get('server') || undefined;
    const hsts = res.headers.has('strict-transport-security');
    const csp = res.headers.has('content-security-policy');

    return {
      httpWebServer: serverHeader,
      httpStatusCode: res.status,
      hstsEnabled: hsts,
      cspPresent: csp,
    };
  } catch {
    return {};
  }
}

function inferMailProvider(mxRecords: string[]): string {
  if (!mxRecords || mxRecords.length === 0) return 'No MX Records Listed';
  const mxStr = mxRecords.join(' ').toLowerCase();
  if (mxStr.includes('google.com') || mxStr.includes('googlemail.com') || mxStr.includes('aspmx')) {
    return 'Google Workspace (Enterprise Gmail)';
  }
  if (mxStr.includes('outlook.com') || mxStr.includes('protection.outlook') || mxStr.includes('microsoft')) {
    return 'Microsoft 365 (Exchange Online)';
  }
  if (mxStr.includes('pphosted.com') || mxStr.includes('proofpoint')) {
    return 'Proofpoint Enterprise Protection';
  }
  if (mxStr.includes('mimecast.com')) {
    return 'Mimecast Email Gateway';
  }
  if (mxStr.includes('protonmail') || mxStr.includes('proton.me')) {
    return 'Proton Mail (Zero-Access Encrypted)';
  }
  if (mxStr.includes('zoho.com')) {
    return 'Zoho Mail';
  }
  if (mxStr.includes('sendgrid.net')) {
    return 'Twilio SendGrid Relay';
  }
  if (mxStr.includes('mailgun.org')) {
    return 'Sinch Mailgun Relay';
  }
  if (mxStr.includes('amazonaws.com') || mxStr.includes('amazonses')) {
    return 'Amazon Simple Email Service (SES)';
  }
  if (mxStr.includes('icloud.com')) {
    return 'Apple iCloud Mail';
  }
  return 'Private / Dedicated Mail Gateway';
}

async function getCrtSubdomainSummary(apexDomain: string, userAgent: string): Promise<{
  crtSubdomainsCount: number;
  crtSubdomainsSample: string[];
  crtWildcardFound: boolean;
}> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);
    const crtData = await fetchCrtNameSubdomains(apexDomain, userAgent);
    clearTimeout(timeout);

    const subdomains = Array.isArray(crtData?.subdomains) ? crtData.subdomains : [];
    const count = typeof crtData?.count === 'number' ? crtData.count : subdomains.length;
    const wildcards = subdomains.filter((s: string) => s.startsWith('*.'));

    return {
      crtSubdomainsCount: count,
      crtSubdomainsSample: subdomains.slice(0, 30),
      crtWildcardFound: wildcards.length > 0,
    };
  } catch {
    return {
      crtSubdomainsCount: 0,
      crtSubdomainsSample: [],
      crtWildcardFound: false,
    };
  }
}

async function buildServerWhoisRecord(rawDomain: string, userAgent: string): Promise<any> {
  const cleanDomain = rawDomain.toLowerCase().trim().replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');
  const rootDomain = extractApexDomain(cleanDomain);
  const tld = rootDomain.split('.').pop() || '';

  // Run comprehensive OSINT probes in parallel
  const [
    whoisResult,
    dnsResolutions,
    attributionResult,
    tlsResult,
    webProbeResult,
    crtResult,
  ] = await Promise.allSettled([
    resolveDomainWhoisAndRdap(cleanDomain, userAgent),
    Promise.allSettled([
      dns.resolveNs(cleanDomain),
      dns.resolve4(cleanDomain),
      dns.resolve6(cleanDomain),
      dns.resolveMx(cleanDomain),
      fetchDnsOverHttps(cleanDomain, 'DS', userAgent),
    ]),
    extractAttributionAndVerification(cleanDomain),
    inspectLiveTlsCert(cleanDomain),
    probeWebServer(cleanDomain, userAgent),
    getCrtSubdomainSummary(rootDomain, userAgent),
  ]);

  const whoisData = whoisResult.status === 'fulfilled' ? whoisResult.value : null;

  // Extract DNS records
  const nameservers: string[] = whoisData?.nameservers ? [...whoisData.nameservers] : [];
  const aRecords: string[] = [];
  const aaaaRecords: string[] = [];
  const mxRecords: string[] = [];
  let dnssec: 'signed' | 'unsigned' = 'unsigned';

  if (dnsResolutions.status === 'fulfilled') {
    const [nsRecs, aRecs, aaaaRecs, mxRecs, dsRecs] = dnsResolutions.value;
    if (nsRecs.status === 'fulfilled' && Array.isArray(nsRecs.value)) {
      nsRecs.value.forEach((ns) => {
        const val = ns.replace(/\.$/, '').toLowerCase();
        if (!nameservers.includes(val)) nameservers.push(val);
      });
    }
    if (aRecs.status === 'fulfilled' && Array.isArray(aRecs.value)) {
      aRecs.value.forEach((ip) => {
        if (!aRecords.includes(ip)) aRecords.push(ip);
      });
    }
    if (aaaaRecs.status === 'fulfilled' && Array.isArray(aaaaRecs.value)) {
      aaaaRecs.value.forEach((ip) => {
        if (!aaaaRecords.includes(ip)) aaaaRecords.push(ip);
      });
    }
    if (mxRecs.status === 'fulfilled' && Array.isArray(mxRecs.value)) {
      mxRecs.value.forEach((mx) => {
        const val = `${mx.exchange} (priority ${mx.priority})`;
        if (!mxRecords.includes(val)) mxRecords.push(val);
      });
    }
    if (dsRecs.status === 'fulfilled' && Array.isArray(dsRecs.value) && dsRecs.value.length > 0) {
      dnssec = 'signed';
    }
  }

  // ASN and BGP Network Intelligence for first A record
  let asnInfo: { asn?: string; asnName?: string; bgpPrefix?: string; subnet24?: string } | null = null;
  if (aRecords.length > 0) {
    try {
      asnInfo = await lookupIpAsn(aRecords[0]);
    } catch {}
  }

  // Calculate age and expiration
  const createdDate = whoisData?.createdDate;
  const expiresDate = whoisData?.expiresDate;

  let domainAgeYears: number | undefined;
  let domainAgeFormatted: string | undefined;
  let daysUntilExpiration: number | undefined;
  let expirationStatus: 'active' | 'expiring-soon' | 'expired' | 'unknown' = 'unknown';

  if (createdDate) {
    const ts = parseFlexibleDateMs(createdDate);
    if (ts !== null) {
      const diffMs = Math.max(0, Date.now() - ts);
      const totalDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      domainAgeYears = +(totalDays / 365.25).toFixed(1);
      const y = Math.floor(totalDays / 365.25);
      const remainingDays = totalDays - Math.floor(y * 365.25);
      const m = Math.floor(remainingDays / 30.4375);
      const d = Math.floor(remainingDays - m * 30.4375);
      domainAgeFormatted = `${y}y ${m}m ${d}d (${totalDays.toLocaleString()} days)`;
    }
  }

  if (expiresDate) {
    const expTs = parseFlexibleDateMs(expiresDate);
    if (expTs !== null) {
      const diffMs = expTs - Date.now();
      daysUntilExpiration = Math.round(diffMs / (1000 * 60 * 60 * 24));
      if (daysUntilExpiration < 0) expirationStatus = 'expired';
      else if (daysUntilExpiration <= 60) expirationStatus = 'expiring-soon';
      else expirationStatus = 'active';
    }
  }

  // Nameserver roots & Provider inference
  const nsRoots = Array.from(
    new Set(nameservers.map((ns) => extractApexDomain(ns)))
  );
  const nsString = nameservers.join(' ').toLowerCase();
  let dnsProvider = 'Custom Infrastructure';
  if (nsString.includes('cloudflare.com')) dnsProvider = 'Cloudflare Managed DNS';
  else if (nsString.includes('awsdns') || nsString.includes('route53')) dnsProvider = 'Amazon Route 53';
  else if (nsString.includes('googledomains') || nsString.includes('googlecloud')) dnsProvider = 'Google Cloud DNS';
  else if (nsString.includes('azure-dns')) dnsProvider = 'Microsoft Azure DNS';
  else if (nsString.includes('domaincontrol') || nsString.includes('godaddy')) dnsProvider = 'GoDaddy DNS';
  else if (nsString.includes('registrar-servers') || nsString.includes('namecheap')) dnsProvider = 'Namecheap DNS';
  else if (nsString.includes('fastly')) dnsProvider = 'Fastly Infrastructure';
  else if (nsString.includes('akam')) dnsProvider = 'Akamai Edge DNS';
  else if (nsString.includes('digitalocean')) dnsProvider = 'DigitalOcean DNS';
  else if (nsString.includes('ovh.')) dnsProvider = 'OVHcloud DNS';

  const mailProvider = inferMailProvider(mxRecords);
  const attributionData = attributionResult.status === 'fulfilled' ? attributionResult.value : null;
  const tlsData = tlsResult.status === 'fulfilled' ? tlsResult.value : null;
  const webData = webProbeResult.status === 'fulfilled' ? webProbeResult.value : null;
  const crtData = crtResult.status === 'fulfilled' ? crtResult.value : null;

  return {
    queryInput: rawDomain,
    domainName: cleanDomain,
    rootDomain,
    tld,
    fetchedAt: Date.now(),
    source: whoisData?.source || 'rdap',

    // Registrar & Authority
    registrar: whoisData?.registrar || 'Protected / Redacted',
    ianaId: whoisData?.ianaId,
    whoisServer: whoisData?.whoisServer,
    abuseContactEmail: whoisData?.abuseContact,
    createdDate,
    updatedDate: whoisData?.updatedDate,
    expiresDate,
    domainAgeYears,
    domainAgeFormatted,
    daysUntilExpiration,
    expirationStatus,
    status: whoisData?.status && whoisData.status.length > 0 ? whoisData.status : ['ok'],
    dnssec,

    // DNS & Infrastructure
    nameservers: nameservers.sort(),
    nameserverRoots: nsRoots.sort(),
    dnsProvider,
    aRecords,
    aaaaRecords,
    mxRecords,
    mailProvider,
    registrantOrg: (whoisData as any)?.registrantOrg,
    registrantCountry: (whoisData as any)?.registrantCountry,
    registrantState: (whoisData as any)?.registrantState,
    registrantCity: (whoisData as any)?.registrantCity,

    // OSINT Network
    asn: asnInfo?.asn,
    asnName: asnInfo?.asnName,
    bgpPrefix: asnInfo?.bgpPrefix,
    subnet24: asnInfo?.subnet24,

    // OSINT TLS
    tlsSubjectCn: tlsData?.tlsSubjectCn,
    tlsSubjectOrg: tlsData?.tlsSubjectOrg,
    tlsIssuerOrg: tlsData?.tlsIssuerOrg,
    tlsIssuerCn: tlsData?.tlsIssuerCn,
    tlsProtocol: tlsData?.tlsProtocol,
    tlsCipher: tlsData?.tlsCipher,
    tlsFingerprint256: tlsData?.tlsFingerprint256,
    tlsSans: tlsData?.tlsSans,

    // OSINT Certificate Transparency
    crtSubdomainsCount: crtData?.crtSubdomainsCount || 0,
    crtSubdomainsSample: crtData?.crtSubdomainsSample || [],
    crtWildcardFound: crtData?.crtWildcardFound || false,

    // OSINT Attribution
    verificationTokens: attributionData?.verificationTokens || [],
    spfRecord: attributionData?.spfRecord,
    spfIncludes: attributionData?.spfIncludes || [],
    dmarcPolicy: attributionData?.dmarcPolicy,
    dmarcRua: attributionData?.dmarcRua,

    // OSINT Web Server
    httpWebServer: webData?.httpWebServer,
    httpStatusCode: webData?.httpStatusCode,
    hstsEnabled: webData?.hstsEnabled,
    cspPresent: webData?.cspPresent,

    rawText:
      whoisData?.rawText ||
      `Domain Name: ${cleanDomain.toUpperCase()}\nRoot Domain: ${rootDomain}\nRegistrar: ${whoisData?.registrar || 'Unknown'}\nName Server: ${nameservers.join(', ')}`,
  };
}

app.get('/api/whois', async (req, res) => {
  const rawDomain = req.query.domain as string;
  if (!rawDomain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  let clean = rawDomain.trim().toLowerCase().replace(/^[a-zA-Z]+:\/\//, '').split('/')[0].split('?')[0].replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');
  if (isPrivateOrLocalHost(clean)) {
    return res.status(400).json({ error: 'Localhost and private IP lookups are disallowed.' });
  }

  try {
    const userAgent = getUserAgent(req);
    const record = await buildServerWhoisRecord(clean, userAgent);
    res.json(record);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'WHOIS lookup failed' });
  }
});

const handleWhoisDiff = async (req: express.Request, res: express.Response) => {
  const domainA = (req.query.domainA || req.body?.domainA) as string;
  const domainB = (req.query.domainB || req.body?.domainB) as string;

  if (!domainA || !domainB) {
    return res.status(400).json({ error: 'Both domainA and domainB parameters are required' });
  }

  const cleanA = domainA.trim().toLowerCase().replace(/^[a-zA-Z]+:\/\//, '').split('/')[0].split('?')[0].replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');
  const cleanB = domainB.trim().toLowerCase().replace(/^[a-zA-Z]+:\/\//, '').split('/')[0].split('?')[0].replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');

  if (isPrivateOrLocalHost(cleanA) || isPrivateOrLocalHost(cleanB)) {
    return res.status(400).json({ error: 'Localhost and private network lookups are disallowed.' });
  }

  try {
    const userAgent = getUserAgent(req);
    const [recA, recB] = await Promise.all([
      buildServerWhoisRecord(cleanA, userAgent),
      buildServerWhoisRecord(cleanB, userAgent),
    ]);

    res.json({
      domainA: recA,
      domainB: recB,
      computedAt: Date.now(),
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to compute WHOIS comparison' });
  }
};

app.get('/api/whois-diff', handleWhoisDiff);
app.post('/api/whois-diff', handleWhoisDiff);

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`./whoisnt server running at http://localhost:${PORT}`);
  });
}

startServer();
