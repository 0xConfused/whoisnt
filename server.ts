// SPDX-License-Identifier: AGPL-3.0-or-later

import express from 'express';
import path from 'path';
import tls from 'tls';
import dns from 'dns/promises';
import net from 'net';
import { createServer as createViteServer } from 'vite';
import { canonicalizeJsonStringify } from './src/utils/jsonSort';
import { parseFlexibleDateMs } from './src/utils/dateUtils';
import { sanitizeDomainInput, isValidDomainFormat, extractApexDomain, prioritizeSubdomainsForRecon } from './src/utils/urlUtils';
import {
  analyzeHtmlRecon,
  extractAnalyticsIdsFromText,
  MAX_HTML_RECON_BYTES,
  MAX_SCRIPT_TEXT_BYTES,
  mergeSubdomainWebRecon,
  readBoundedResponseText,
  sanitizeHttpHeaders,
  selectFirstPartyScriptsForInspection,
  type SubdomainWebProbeEntry,
} from './src/utils/htmlRecon';

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
  const safeId = id.replace(/[^a-zA-Z0-9.:_-]/g, '').slice(0, 64) || '127.0.0.1';
  return `Mozilla/5.0 (compatible; 0xCONFUSED./whoisnt; user: ${safeId})`;
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
  seenHops.add(cleanUrl(initialUrl) || initialUrl);

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

      const normalizedNext = cleanUrl(nextUrl) || nextUrl;
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

function cleanUrl(rawUrl: string): string | null {
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

    parsed.hash = '';
    if (parsed.search) {
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
  let abuseContact = '';
  let registrantOrg = '';
  let registrantCountry = '';
  let registrantState = '';

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
    createdDate: createdDate || undefined,
    updatedDate: updatedDate || undefined,
    expiresDate: expiresDate || undefined,
    status,
    nameservers,
    abuseContact: abuseContact || undefined,
    registrantOrg: registrantOrg || undefined,
    registrantCountry: registrantCountry || undefined,
    registrantState: registrantState || undefined,
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
    createdDate,
    updatedDate,
    expiresDate,
    status,
    nameservers,
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

async function fetchCrtNameSubdomains(
  apexDomain: string,
  userAgentOrReq?: string | express.Request,
  timeoutMs = 9000
): Promise<any> {
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
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
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

async function lookupIpAsn(ip: string): Promise<{ asn?: string; asnName?: string; subnet24?: string } | null> {
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
  tlsValidityNotBefore?: string;
  tlsValidityNotAfter?: string;
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

          socket.destroy();
          resolve({
            tlsSubjectCn: (cert?.subject && (cert.subject as any).CN) || undefined,
            tlsSubjectOrg: (cert?.subject && (cert.subject as any).O) || undefined,
            tlsIssuerOrg: (cert?.issuer && (cert.issuer as any).O) || undefined,
            tlsIssuerCn: (cert?.issuer && (cert.issuer as any).CN) || undefined,
            tlsProtocol: protocol || undefined,
            tlsCipher: cipher || undefined,
            tlsValidityNotBefore: cert?.valid_from || undefined,
            tlsValidityNotAfter: cert?.valid_to || undefined,
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

function normalizeFinalUrlForDedup(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    u.hash = '';
    u.hostname = u.hostname.toLowerCase();
    if ((u.protocol === 'https:' && u.port === '443') || (u.protocol === 'http:' && u.port === '80')) {
      u.port = '';
    }
    if (!u.pathname) u.pathname = '/';
    return u.toString();
  } catch {
    return rawUrl.trim().toLowerCase();
  }
}

async function probeSingleHostWebRecon(
  host: string,
  userAgent: string,
  allowHttpFallback: boolean,
  seenFinalUrls: Set<string>,
  seenScriptUrls: Set<string>,
  scriptBudget: { remaining: number }
): Promise<SubdomainWebProbeEntry | null> {
  if (!isValidDomainFormat(host) || isPrivateOrLocalHost(host)) return null;

  let res: Response | null = null;
  let attemptUrl = `https://${host}`;
  const schemes = allowHttpFallback ? ['https', 'http'] : ['https'];

  for (const scheme of schemes) {
    attemptUrl = `${scheme}://${host}`;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2400);
      const r = await safeFetch(attemptUrl, {
        method: 'GET',
        headers: {
          'User-Agent': userAgent,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        signal: controller.signal,
        maxRedirects: 4,
      });
      clearTimeout(timeout);
      res = r;
      break;
    } catch {
      res = null;
    }
  }

  if (!res) return null;

  const finalUrl = ((res as any).finalUrl as string) || res.url || attemptUrl;
  const dedupFinalUrl = normalizeFinalUrlForDedup(finalUrl);
  const sanitizedHeaders = sanitizeHttpHeaders(res.headers);
  const serverHeader = sanitizedHeaders['server'] || undefined;
  const contentType = (res.headers.get('content-type') || '').toLowerCase();

  const isHtmlLike =
    !contentType ||
    contentType.includes('text/html') ||
    contentType.includes('application/xhtml') ||
    contentType.includes('text/plain') ||
    contentType.includes('application/xml') ||
    contentType.includes('text/xml');

  const httpHeaderSummary = Object.keys(sanitizedHeaders)
    .sort()
    .map((k) => `${k}: ${sanitizedHeaders[k]}`);

  if (!isHtmlLike || seenFinalUrls.has(dedupFinalUrl)) {
    try {
      await res.body?.cancel();
    } catch {}
    return {
      host,
      httpWebServer: serverHeader,
      httpStatusCode: res.status,
      webFinalUrl: finalUrl,
      fallbackHeaders: httpHeaderSummary,
    };
  }
  seenFinalUrls.add(dedupFinalUrl);

  let htmlText = '';
  try {
    htmlText = await readBoundedResponseText(res, MAX_HTML_RECON_BYTES);
  } catch {
    htmlText = '';
  }

  const recon = analyzeHtmlRecon(htmlText, finalUrl, sanitizedHeaders, host);

  // Bounded first-party script UTF-8 text scan (strictly non-executed, SSRF-guarded, deduplicated across hosts)
  const analyticsSet = new Set<string>(recon.analyticsIds);
  let inspectedScriptsCount = 0;

  if (scriptBudget.remaining > 0) {
    const allowedForHost = Math.min(2, scriptBudget.remaining);
    const candidateScripts = selectFirstPartyScriptsForInspection(recon.scriptUrls, host, allowedForHost * 2)
      .filter((scriptUrl) => {
        const normScript = normalizeFinalUrlForDedup(scriptUrl);
        if (seenScriptUrls.has(normScript)) return false;
        seenScriptUrls.add(normScript);
        return true;
      })
      .slice(0, allowedForHost);
    scriptBudget.remaining = Math.max(0, scriptBudget.remaining - candidateScripts.length);

    if (candidateScripts.length > 0) {
      const scriptResults = await Promise.allSettled(
        candidateScripts.map(async (scriptUrl) => {
          const sc = new AbortController();
          const timer = setTimeout(() => sc.abort(), 2000);
          try {
            const sRes = await safeFetch(scriptUrl, {
              method: 'GET',
              headers: {
                'User-Agent': userAgent,
                Accept: 'application/javascript,text/javascript,text/plain,*/*;q=0.5',
              },
              signal: sc.signal,
              maxRedirects: 2,
            });
            clearTimeout(timer);
            if (!sRes.ok) return null;
            const sCt = (sRes.headers.get('content-type') || '').toLowerCase();
            if (sCt && !sCt.includes('javascript') && !sCt.includes('text/') && !sCt.includes('ecmascript') && !sCt.includes('json')) {
              try {
                await sRes.body?.cancel();
              } catch {}
              return null;
            }
            return await readBoundedResponseText(sRes, MAX_SCRIPT_TEXT_BYTES);
          } catch {
            clearTimeout(timer);
            return null;
          }
        })
      );

      for (const r of scriptResults) {
        if (r.status === 'fulfilled' && r.value) {
          inspectedScriptsCount++;
          const scriptAnalytics = extractAnalyticsIdsFromText(r.value);
          scriptAnalytics.forEach((id) => analyticsSet.add(id));
        }
      }
    }
  }

  recon.analyticsIds = Array.from(analyticsSet).sort();

  return {
    host,
    httpWebServer: serverHeader,
    httpStatusCode: res.status,
    webFinalUrl: finalUrl,
    inspectedScriptsCount,
    recon,
  };
}

async function probeWebPageAndHeaders(
  domain: string,
  userAgent: string,
  discoveredSubdomains: string[] = []
) {
  const candidates = prioritizeSubdomainsForRecon(domain, discoveredSubdomains, 24).filter(
    (h) => !isPrivateOrLocalHost(h)
  );
  const seenFinalUrls = new Set<string>();
  const seenScriptUrls = new Set<string>();
  const scriptBudget = { remaining: 10 };
  const entries: SubdomainWebProbeEntry[] = [];
  const deadline = Date.now() + 8500;

  let idx = 0;
  const concurrency = Math.min(8, Math.max(1, candidates.length));
  const workers = Array.from({ length: concurrency }, async () => {
    while (idx < candidates.length && Date.now() < deadline) {
      const host = candidates[idx++];
      const allowHttpFallback = host === domain || host === `www.${domain}`;
      const entry = await probeSingleHostWebRecon(
        host,
        userAgent,
        allowHttpFallback,
        seenFinalUrls,
        seenScriptUrls,
        scriptBudget
      );
      if (entry) {
        entries.push(entry);
      }
    }
  });

  await Promise.all(workers);
  return mergeSubdomainWebRecon(domain, entries, candidates.length, 'server-direct');
}

async function fetchHackerTargetZone(
  rootDomain: string,
  userAgent: string
): Promise<{ records: Array<{ host: string; ip: string }>; hosts: string[] }> {
  const records: Array<{ host: string; ip: string }> = [];
  const hostSet = new Set<string>();
  if (!isValidDomainFormat(rootDomain) || isPrivateOrLocalHost(rootDomain)) {
    return { records, hosts: [] };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    const res = await safeFetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(rootDomain)}`, {
      signal: controller.signal,
      headers: { 'User-Agent': userAgent },
      maxRedirects: 2,
    });
    clearTimeout(timer);
    if (!res.ok) return { records, hosts: [] };
    const text = await res.text();
    if (!text || text.includes('error') || text.includes('API count exceeded')) {
      return { records, hosts: [] };
    }

    for (const line of text.split('\n').slice(0, 500)) {
      const [hostRaw, ipRaw] = line.split(',');
      const host = hostRaw?.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
      const ip = ipRaw?.trim();
      if (!host || !ip) continue;
      if (host !== rootDomain && !host.endsWith(`.${rootDomain}`)) continue;
      if (!isValidDomainFormat(host) || isPrivateOrLocalHost(host)) continue;
      hostSet.add(host);
      records.push({ host, ip });
    }
  } catch {}

  return { records, hosts: Array.from(hostSet) };
}

async function fetchServerPassiveDns(
  rootDomain: string,
  userAgent: string,
  discoveredSubdomains: string[] = [],
  preloadedHtRecords: Array<{ host: string; ip: string }> = []
): Promise<{
  passiveDnsDisplay: string[];
  passiveDnsIps: string[];
  pdnsQueriedSubdomainsCount: number;
}> {
  const ipSet = new Set<string>();
  const displayMap = new Map<string, string>();
  const addPdnsDisplay = (rr: string, host: string, ans: string, span = '') => {
    const cleanRr = rr.toUpperCase().trim();
    const cleanHost = host.toLowerCase().trim().replace(/\.$/, '');
    const cleanAns = ans.trim();
    if (!cleanRr || !cleanHost || !cleanAns) return;
    const key = `${cleanRr}|${cleanHost}|${cleanAns.toLowerCase()}`;
    const formatted = `${cleanRr} | ${cleanHost} -> ${cleanAns}${span}`;
    const existing = displayMap.get(key);
    if (!existing || (span && !existing.includes('['))) {
      displayMap.set(key, formatted);
    }
  };

  for (const rec of preloadedHtRecords) {
    if (!rec.host || !rec.ip) continue;
    if (/^[\da-fA-F:.]+$/.test(rec.ip)) ipSet.add(rec.ip);
    addPdnsDisplay(rec.ip.includes(':') ? 'AAAA' : 'A', rec.host, rec.ip);
  }

  const pdnsTargets = prioritizeSubdomainsForRecon(rootDomain, discoveredSubdomains, 16).filter(
    (h) => !isPrivateOrLocalHost(h)
  );
  const mnemonicTargets = Array.from(new Set([rootDomain, `*.${rootDomain}`, ...pdnsTargets]));
  const ripeTargets = pdnsTargets.slice(0, 12);

  const queryMnemonicTarget = async (target: string) => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2500);
      const res = await safeFetch(`https://api.mnemonic.no/pdns/v3/${encodeURIComponent(target)}?limit=40`, {
        signal: controller.signal,
        headers: { 'User-Agent': userAgent, Accept: 'application/json' },
        maxRedirects: 2,
      });
      clearTimeout(timer);
      if (!res.ok) return;
      const json = await res.json();
      if (!Array.isArray(json?.data)) return;
      for (const item of json.data) {
        const q = String(item.query || target).toLowerCase();
        const rr = String(item.rrtype || '').toUpperCase();
        const ans = String(item.answer || '').trim();
        if (!rr || !ans) continue;
        const fsMs = Number(item.firstSeenTimestamp || item.createdTimestamp || 0);
        const lsMs = Number(item.lastSeenTimestamp || item.lastUpdatedTimestamp || 0);
        const firstSeen = fsMs > 0 ? new Date(fsMs).toISOString().slice(0, 10) : undefined;
        const lastSeen = lsMs > 0 ? new Date(lsMs).toISOString().slice(0, 10) : undefined;
        if ((rr === 'A' || rr === 'AAAA') && /^[\da-fA-F:.]+$/.test(ans)) {
          ipSet.add(ans);
        }
        const span = firstSeen && lastSeen ? ` [${firstSeen}..${lastSeen}]` : firstSeen ? ` [${firstSeen}]` : '';
        addPdnsDisplay(rr, q, ans, span);
      }
    } catch {}
  };

  const queryRipeDnsChainTarget = async (target: string) => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2500);
      const res = await safeFetch(`https://stat.ripe.net/data/dns-chain/data.json?resource=${encodeURIComponent(target)}`, {
        signal: controller.signal,
        headers: { 'User-Agent': userAgent, Accept: 'application/json' },
        maxRedirects: 2,
      });
      clearTimeout(timer);
      if (!res.ok) return;
      const json = await res.json();
      const forwardNodes = json?.data?.forward_nodes;
      if (forwardNodes && typeof forwardNodes === 'object') {
        for (const [hostKey, vals] of Object.entries(forwardNodes)) {
          if (!Array.isArray(vals)) continue;
          for (const rawAns of vals) {
            const ans = String(rawAns).trim();
            if (!ans) continue;
            if (/^[\da-fA-F:.]+$/.test(ans)) ipSet.add(ans);
            addPdnsDisplay(ans.includes(':') ? 'AAAA' : 'A', hostKey, ans);
          }
        }
      }
    } catch {}
  };

  const runBatched = async (items: string[], concurrency: number, workerFn: (item: string) => Promise<void>) => {
    let i = 0;
    const deadline = Date.now() + 5500;
    const workers = Array.from({ length: Math.min(concurrency, Math.max(1, items.length)) }, async () => {
      while (i < items.length && Date.now() < deadline) {
        const nextItem = items[i++];
        await workerFn(nextItem);
      }
    });
    await Promise.all(workers);
  };

  await Promise.allSettled([
    runBatched(mnemonicTargets, 6, queryMnemonicTarget),
    runBatched(ripeTargets, 6, queryRipeDnsChainTarget),
  ]);

  return {
    passiveDnsDisplay: Array.from(displayMap.values()).sort().slice(0, 250),
    passiveDnsIps: Array.from(ipSet).sort(),
    pdnsQueriedSubdomainsCount: pdnsTargets.length,
  };
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
  allSubdomains: string[];
  crtWildcardFound: boolean;
}> {
  try {
    const crtData = await fetchCrtNameSubdomains(apexDomain, userAgent, 4500);
    let subdomains: string[] = Array.isArray(crtData?.subdomains) ? crtData.subdomains : [];

    // Fallback to Certspotter CT API if crt.name returned no subdomains
    if (subdomains.length === 0 && isValidDomainFormat(apexDomain) && !isPrivateOrLocalHost(apexDomain)) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3500);
        const res = await safeFetch(
          `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(apexDomain)}&include_subdomains=true&expand=dns_names`,
          {
            signal: controller.signal,
            headers: { Accept: 'application/json', 'User-Agent': userAgent },
            maxRedirects: 2,
          }
        );
        clearTimeout(timeout);
        if (res.ok) {
          const items = await res.json();
          if (Array.isArray(items)) {
            const fallbackSet = new Set<string>();
            for (const item of items) {
              if (!Array.isArray(item?.dns_names)) continue;
              for (const name of item.dns_names) {
                const cleaned = String(name).toLowerCase().trim().replace(/^\.+|\.+$/g, '');
                const base = cleaned.startsWith('*.') ? cleaned.slice(2) : cleaned;
                if (base && (base === apexDomain || base.endsWith(`.${apexDomain}`))) {
                  fallbackSet.add(cleaned);
                }
              }
            }
            subdomains = Array.from(fallbackSet).sort();
          }
        }
      } catch {}
    }

    const count = typeof crtData?.count === 'number' && crtData.count > 0 ? crtData.count : subdomains.length;
    const wildcards = subdomains.filter((s: string) => s.startsWith('*.'));

    return {
      crtSubdomainsCount: count,
      crtSubdomainsSample: subdomains.slice(0, 80),
      allSubdomains: subdomains,
      crtWildcardFound: wildcards.length > 0,
    };
  } catch {
    return {
      crtSubdomainsCount: 0,
      crtSubdomainsSample: [],
      allSubdomains: [],
      crtWildcardFound: false,
    };
  }
}

async function buildServerWhoisRecord(rawDomain: string, userAgent: string): Promise<any> {
  const cleanDomain = rawDomain.toLowerCase().trim().replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');
  const rootDomain = extractApexDomain(cleanDomain);

  // Phase 1: WHOIS/RDAP, DNS, Attribution, TLS, and Subdomain Discovery (CT + HackerTarget)
  const [
    whoisResult,
    dnsResolutions,
    attributionResult,
    tlsResult,
    crtResult,
    hackerTargetResult,
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
    getCrtSubdomainSummary(rootDomain, userAgent),
    fetchHackerTargetZone(rootDomain, userAgent),
  ]);

  const crtData = crtResult.status === 'fulfilled' ? crtResult.value : null;
  const htData = hackerTargetResult.status === 'fulfilled' ? hackerTargetResult.value : null;
  const discoveredSubdomains = Array.from(
    new Set(
      [...(crtData?.allSubdomains || []), ...(htData?.hosts || [])]
        .map((h) => String(h || '').toLowerCase().trim().replace(/^\.+|\.+$/g, ''))
        .filter(Boolean)
    )
  );

  // Phase 2: Search discovered subdomains for Web Recon and Passive DNS
  const [webProbeResult, passiveDnsResult] = await Promise.allSettled([
    probeWebPageAndHeaders(cleanDomain, userAgent, discoveredSubdomains),
    fetchServerPassiveDns(rootDomain, userAgent, discoveredSubdomains, htData?.records || []),
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
  let asnInfo: { asn?: string; asnName?: string; subnet24?: string } | null = null;
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

  // Provider inference
  const nsString = nameservers.join(' ').toLowerCase();
  let dnsProvider = 'Custom Infrastructure';
  if (nsString.includes('cloudflare.com')) dnsProvider = 'Cloudflare Managed DNS';
  else if (nsString.includes('awsdns') || nsString.includes('route53')) dnsProvider = 'Amazon Route 53';
  else if (nsString.includes('googledomains.com') || nsString.includes('googlecloud')) dnsProvider = 'Google Cloud DNS';
  else if (nsString.includes('azure-dns')) dnsProvider = 'Microsoft Azure DNS';
  else if (nsString.includes('domaincontrol') || nsString.includes('godaddy')) dnsProvider = 'GoDaddy DNS';
  else if (nsString.includes('registrar-servers') || nsString.includes('namecheap')) dnsProvider = 'Namecheap DNS';
  else if (nsString.includes('fastly')) dnsProvider = 'Fastly Infrastructure';
  else if (nsString.includes('akam')) dnsProvider = 'Akamai Edge DNS';
  else if (nsString.includes('digitalocean')) dnsProvider = 'DigitalOcean DNS';
  else if (nsString.includes('ovh.')) dnsProvider = 'OVHcloud DNS';

  const mailProvider = inferMailProvider(mxRecords);
  const attributionData = attributionResult.status === 'fulfilled' ? attributionResult.value : null;
  let tlsData = tlsResult.status === 'fulfilled' ? tlsResult.value : null;
  const webData = webProbeResult.status === 'fulfilled' ? webProbeResult.value : null;
  const pdnsData = passiveDnsResult.status === 'fulfilled' ? passiveDnsResult.value : null;

  if (!tlsData?.tlsIssuerCn && !tlsData?.tlsSubjectCn) {
    const fallbackTlsHost = webData?.webReconReachableHosts?.find((h) => h !== cleanDomain);
    if (fallbackTlsHost && isValidDomainFormat(fallbackTlsHost) && !isPrivateOrLocalHost(fallbackTlsHost)) {
      try {
        tlsData = await inspectLiveTlsCert(fallbackTlsHost);
      } catch {}
    }
  }

  return {
    domainName: cleanDomain,
    rootDomain,
    source: whoisData?.source || 'rdap',

    // Registrar & Authority
    registrar: whoisData?.registrar || 'Protected / Redacted',
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
    dnsProvider,
    aRecords,
    aaaaRecords,
    mailProvider,
    registrantOrg: (whoisData as any)?.registrantOrg,
    registrantCountry: (whoisData as any)?.registrantCountry,
    registrantState: (whoisData as any)?.registrantState,

    // OSINT Network & Passive DNS
    asn: asnInfo?.asn,
    asnName: asnInfo?.asnName,
    subnet24: asnInfo?.subnet24,
    passiveDnsDisplay: pdnsData?.passiveDnsDisplay || [],
    passiveDnsIps: pdnsData?.passiveDnsIps || [],
    pdnsQueriedSubdomainsCount: pdnsData?.pdnsQueriedSubdomainsCount,

    // OSINT TLS
    tlsSubjectCn: tlsData?.tlsSubjectCn,
    tlsSubjectOrg: tlsData?.tlsSubjectOrg,
    tlsIssuerOrg: tlsData?.tlsIssuerOrg,
    tlsIssuerCn: tlsData?.tlsIssuerCn,
    tlsProtocol: tlsData?.tlsProtocol,
    tlsCipher: tlsData?.tlsCipher,
    tlsValidityNotBefore: tlsData?.tlsValidityNotBefore,
    tlsValidityNotAfter: tlsData?.tlsValidityNotAfter,

    // OSINT Certificate Transparency
    crtSubdomainsCount: crtData?.crtSubdomainsCount || 0,
    crtSubdomainsSample: crtData?.crtSubdomainsSample || [],
    crtWildcardFound: crtData?.crtWildcardFound || false,

    // OSINT Attribution
    verificationTokens: attributionData?.verificationTokens || [],
    htmlVerificationTokens: webData?.htmlVerificationTokens || [],
    analyticsIds: webData?.analyticsIds || [],
    footerCopyrights: webData?.footerCopyrights || [],
    copyrightEntities: webData?.copyrightEntities || [],
    spfRecord: attributionData?.spfRecord,
    spfIncludes: attributionData?.spfIncludes || [],
    dmarcPolicy: attributionData?.dmarcPolicy,
    dmarcRua: attributionData?.dmarcRua,

    // OSINT Web Server, Headers, DOM, Resources & Tech Stack
    httpWebServer: webData?.httpWebServer,
    httpStatusCode: webData?.httpStatusCode,
    httpHeaderSummary: webData?.httpHeaderSummary || [],
    cspExternalDomains: webData?.cspExternalDomains || [],
    webReconMode: webData?.webReconMode,
    webFinalUrl: webData?.webFinalUrl,
    inspectedScriptsCount: webData?.inspectedScriptsCount || 0,
    webReconProbedHostsCount: webData?.webReconProbedHostsCount,
    webReconReachableHosts: webData?.webReconReachableHosts || [],
    htmlTitle: webData?.htmlTitle,
    htmlDescription: webData?.htmlDescription,
    htmlGenerator: webData?.htmlGenerator,
    htmlAuthor: webData?.htmlAuthor,
    htmlRobots: webData?.htmlRobots,
    canonicalUrl: webData?.canonicalUrl,
    openGraphSiteName: webData?.openGraphSiteName,
    twitterSite: webData?.twitterSite,
    domMarkers: webData?.domMarkers || [],
    domStats: webData?.domStats,
    scriptUrls: webData?.scriptUrls || [],
    resourceSummary: webData?.resourceSummary || [],
    technologies: webData?.technologies || [],
    externalDomains: webData?.externalDomains || [],

    rawText:
      whoisData?.rawText ||
      `Domain Name: ${cleanDomain.toUpperCase()}\nRoot Domain: ${rootDomain}\nRegistrar: ${whoisData?.registrar || 'Unknown'}\nName Server: ${nameservers.join(', ')}`,
  };
}

app.get('/api/whois', async (req, res) => {
  const rawDomain = req.query.domain;
  if (typeof rawDomain !== 'string' || !rawDomain.trim()) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  const clean = sanitizeDomainInput(rawDomain);
  if (!clean || !isValidDomainFormat(clean) || isPrivateOrLocalHost(clean)) {
    return res.status(400).json({ error: 'Invalid or disallowed domain parameter. Only valid public domain names are permitted.' });
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
  const domainA = req.query.domainA ?? req.body?.domainA;
  const domainB = req.query.domainB ?? req.body?.domainB;

  if (typeof domainA !== 'string' || typeof domainB !== 'string' || !domainA.trim() || !domainB.trim()) {
    return res.status(400).json({ error: 'Both domainA and domainB parameters are required' });
  }

  const cleanA = sanitizeDomainInput(domainA);
  const cleanB = sanitizeDomainInput(domainB);

  if (
    !cleanA ||
    !cleanB ||
    !isValidDomainFormat(cleanA) ||
    !isValidDomainFormat(cleanB) ||
    isPrivateOrLocalHost(cleanA) ||
    isPrivateOrLocalHost(cleanB)
  ) {
    return res.status(400).json({ error: 'Invalid or disallowed domain parameters. Only valid public domain names are permitted.' });
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

function escapeHtmlAttr(val: string): string {
  return val
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function sanitizePreviewHtml(rawHtml: string, baseUrl: string): string {
  let html = rawHtml;

  // Strip executable and nested-browsing elements completely
  html = html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<script\b[^>]*>[\s\S]*/gi, '')
    .replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, '')
    .replace(/<iframe\b[^>]*\/?>/gi, '')
    .replace(/<frame\b[^>]*>[\s\S]*?<\/frame>/gi, '')
    .replace(/<frame\b[^>]*\/?>/gi, '')
    .replace(/<frameset\b[^>]*>[\s\S]*?<\/frameset>/gi, '')
    .replace(/<object\b[^>]*>[\s\S]*?<\/object>/gi, '')
    .replace(/<embed\b[^>]*\/?>/gi, '')
    .replace(/<applet\b[^>]*>[\s\S]*?<\/applet>/gi, '')
    .replace(/<foreignObject\b[^>]*>[\s\S]*?<\/foreignObject>/gi, '')
    .replace(/<base\b[^>]*>/gi, '')
    .replace(/<meta\b[^>]*http-equiv\s*=\s*["']?\s*(?:refresh|content-security-policy|set-cookie)[^>]*>/gi, '')
    .replace(/<link\b[^>]*\bas\s*=\s*["']?\s*(?:script|worker|sharedworker|serviceworker)[^>]*>/gi, '');

  // Scrub inline event handlers (on*), srcdoc, and dangerous URI schemes inside element tags
  html = html.replace(/<([a-zA-Z][a-zA-Z0-9:-]*)(\s+[^>]*)?>/g, (fullMatch, tagName: string, rawAttrs?: string) => {
    if (!rawAttrs) return fullMatch;
    let attrs = rawAttrs;

    // Remove on* event handler attributes and srcdoc repeatedly to handle adjacent attributes
    let prev = '';
    while (attrs !== prev) {
      prev = attrs;
      attrs = attrs
        .replace(/\s+on[a-z0-9_-]*\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
        .replace(/\s+srcdoc\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
    }

    // Neutralize javascript:, vbscript:, or data:text/html in URL-bearing attributes
    attrs = attrs.replace(
      /\b(href|src|action|formaction|xlink:href|poster|data)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi,
      (attrMatch, attrName: string, _quoted: string, dVal?: string, sVal?: string, uVal?: string) => {
        const rawVal = (dVal ?? sVal ?? uVal ?? '').replace(/[\u0000-\u0020]+/g, '').toLowerCase();
        if (
          rawVal.startsWith('javascript:') ||
          rawVal.startsWith('vbscript:') ||
          rawVal.startsWith('data:text/html') ||
          rawVal.startsWith('data:application/xhtml')
        ) {
          return `${attrName}="about:blank"`;
        }
        return attrMatch;
      }
    );

    const selfClosing = rawAttrs.trimEnd().endsWith('/') ? '/' : '';
    const cleanedAttrs = attrs.replace(/\/\s*$/, '');
    return `<${tagName}${cleanedAttrs}${selfClosing}>`;
  });

  let safeBaseTag = '';
  try {
    const parsedBase = new URL(baseUrl);
    if (parsedBase.protocol === 'http:' || parsedBase.protocol === 'https:') {
      safeBaseTag = `<base href="${escapeHtmlAttr(parsedBase.href)}">`;
    }
  } catch {}

  const cspMeta =
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'none\'; object-src \'none\'; base-uri https: http:; style-src \'unsafe-inline\' https: http:; font-src https: http: data:; img-src https: http: data:; media-src \'none\'; frame-src \'none\'; connect-src \'none\'; form-action \'none\';">';
  const readOnlyStyle =
    '<style>a,button,input,select,textarea,form{pointer-events:none!important;}</style>';
  const headInjection = `${cspMeta}${safeBaseTag}${readOnlyStyle}`;

  if (/<head\b[^>]*>/i.test(html)) {
    return html.replace(/<head\b[^>]*>/i, (m) => `${m}${headInjection}`);
  }
  if (/<html\b[^>]*>/i.test(html)) {
    return html.replace(/<html\b[^>]*>/i, (m) => `${m}<head>${headInjection}</head>`);
  }
  return `<!doctype html><html><head><meta charset="utf-8">${headInjection}</head><body>${html}</body></html>`;
}

app.get('/api/preview', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  const rawDomain = req.query.domain;
  if (typeof rawDomain !== 'string' || !rawDomain.trim()) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  const clean = sanitizeDomainInput(rawDomain);

  if (!clean || !isValidDomainFormat(clean) || isPrivateOrLocalHost(clean)) {
    return res.status(400).json({ error: 'Invalid or disallowed domain parameter. Only valid public domain names are permitted.' });
  }

  const userAgent = getUserAgent(req);
  let targetRes: Response | null = null;
  let attemptUrl = `https://${clean}`;

  for (const scheme of ['https', 'http']) {
    attemptUrl = `${scheme}://${clean}`;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 6000);
      const r = await safeFetch(attemptUrl, {
        method: 'GET',
        headers: {
          'User-Agent': userAgent,
          Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
        },
        signal: controller.signal,
        maxRedirects: 4,
      });
      clearTimeout(timeout);
      targetRes = r;
      break;
    } catch {
      targetRes = null;
    }
  }

  if (!targetRes) {
    return res.status(502).json({ error: `Unable to connect to ${clean} over HTTPS or HTTP.` });
  }

  const finalUrl = ((targetRes as any).finalUrl as string) || targetRes.url || attemptUrl;
  const contentType = (targetRes.headers.get('content-type') || '').toLowerCase();
  const isHtmlLike =
    !contentType ||
    contentType.includes('text/html') ||
    contentType.includes('application/xhtml') ||
    contentType.includes('text/plain');

  if (!isHtmlLike) {
    try {
      await targetRes.body?.cancel();
    } catch {}
    return res.status(415).json({
      error: `Target returned non-HTML content (${contentType.split(';')[0] || 'unknown'}).`,
      statusCode: targetRes.status,
      finalUrl,
    });
  }

  try {
    const rawHtml = await readBoundedResponseText(targetRes, MAX_HTML_RECON_BYTES);
    if (!rawHtml.trim()) {
      return res.status(502).json({
        error: `Target returned an empty response body (HTTP ${targetRes.status}).`,
        statusCode: targetRes.status,
        finalUrl,
      });
    }
    const sanitizedHtml = sanitizePreviewHtml(rawHtml, finalUrl);
    return res.json({
      html: sanitizedHtml,
      finalUrl,
      statusCode: targetRes.status,
    });
  } catch (err: any) {
    return res.status(502).json({ error: err?.message || 'Failed to read target HTML for preview.' });
  }
});

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
