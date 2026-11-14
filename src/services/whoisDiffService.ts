// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  WhoisDomainRecord,
  FieldDiffItem,
  WhoisDiffResult,
  WhoisDiffSummary,
  SharedLinkageInsight,
  TextDiffLine,
  DiffStatus,
} from '../types';
import { extractApexDomain } from '../utils/urlUtils';
import { enrichDomainWithBrowserDns, queryBrowserDoh } from './browserDnsService';
import { canonicalizeJsonStringify, formatCanonicalJsonText } from '../utils/jsonSort';
import { parseFlexibleDateMs } from '../utils/dateUtils';

export function sanitizeDomainInput(raw: string): string {
  if (!raw) return '';
  let str = raw.trim();
  str = str.replace(/^[a-zA-Z]+:\/\//, '');
  str = str.split('/')[0];
  str = str.split('?')[0];
  str = str.split('#')[0];
  str = str.replace(/:\d+$/, '');
  str = str.replace(/^\.+|\.+$/g, '');
  return str.toLowerCase();
}

export function isValidDomainFormat(domain: string): boolean {
  if (!domain || domain.length < 3 || domain.length > 253) return false;
  if (!domain.includes('.')) return false;
  // RFC 1035 / RFC 1123 domain syntax
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
  return domainRegex.test(domain);
}

export function inferDnsProvider(nameservers: string[]): string {
  if (!nameservers || nameservers.length === 0) return 'Undetermined';
  const nsString = nameservers.join(' ').toLowerCase();

  if (nsString.includes('cloudflare.com')) return 'Cloudflare Managed DNS';
  if (nsString.includes('awsdns') || nsString.includes('route53')) return 'Amazon Route 53';
  if (nsString.includes('googledomains.com') || nsString.includes('googlecloud.com')) return 'Google Cloud DNS';
  if (nsString.includes('azure-dns')) return 'Microsoft Azure DNS';
  if (nsString.includes('domaincontrol.com') || nsString.includes('godaddy')) return 'GoDaddy DNS';
  if (nsString.includes('registrar-servers.com') || nsString.includes('namecheap')) return 'Namecheap DNS';
  if (nsString.includes('fastly')) return 'Fastly Infrastructure';
  if (nsString.includes('akam')) return 'Akamai Edge DNS';
  if (nsString.includes('digitalocean.com')) return 'DigitalOcean DNS';
  if (nsString.includes('ovh.net') || nsString.includes('ovh.com')) return 'OVHcloud DNS';
  if (nsString.includes('he.net')) return 'Hurricane Electric DNS';
  if (nsString.includes('dnsmadeeasy.com')) return 'DNS Made Easy';
  if (nsString.includes('dynect.net')) return 'Oracle Dyn';
  if (nsString.includes('nsone.net')) return 'NS1 / IBM DNS';
  if (nsString.includes('hetzner')) return 'Hetzner DNS';
  if (nsString.includes('linode.com')) return 'Akamai / Linode DNS';

  // Extract apex of first NS
  const firstNs = nameservers[0];
  const apex = extractApexDomain(firstNs);
  return apex ? `${apex.toUpperCase()} DNS` : 'Custom Infrastructure';
}

export function parseDateToTimestamp(dateStr?: string): number | null {
  return parseFlexibleDateMs(dateStr);
}

export function formatDomainAge(createdDateStr?: string): { years: number; formatted: string } | null {
  const ts = parseDateToTimestamp(createdDateStr);
  if (!ts) return null;

  const now = Date.now();
  const diffMs = Math.max(0, now - ts);
  const totalDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const years = +(totalDays / 365.25).toFixed(1);

  const y = Math.floor(totalDays / 365.25);
  const remainingDaysAfterY = totalDays - Math.floor(y * 365.25);
  const m = Math.floor(remainingDaysAfterY / 30.4375);
  const d = Math.floor(remainingDaysAfterY - m * 30.4375);

  let formatted = '';
  if (y > 0) formatted += `${y}y `;
  if (m > 0 || y > 0) formatted += `${m}m `;
  formatted += `${d}d (${totalDays.toLocaleString()} days)`;

  return { years, formatted: formatted.trim() };
}

export function formatExpirationCountdown(expiresDateStr?: string): { days: number; status: 'active' | 'expiring-soon' | 'expired' } | null {
  const ts = parseDateToTimestamp(expiresDateStr);
  if (!ts) return null;

  const now = Date.now();
  const diffMs = ts - now;
  const days = Math.round(diffMs / (1000 * 60 * 60 * 24));

  if (days < 0) {
    return { days, status: 'expired' };
  } else if (days <= 60) {
    return { days, status: 'expiring-soon' };
  }
  return { days, status: 'active' };
}

export const EPP_STATUS_DEFINITIONS: Record<string, { desc: string; severity: 'normal' | 'caution' | 'critical' }> = {
  clienttransferprohibited: { desc: 'Prevents unauthorized registrar transfers (Registrar Lock)', severity: 'normal' },
  clientdeleteprohibited: { desc: 'Prevents accidental or malicious domain deletion', severity: 'normal' },
  clientupdateprohibited: { desc: 'Prevents unauthorized DNS or contact modifications', severity: 'normal' },
  clientrenewprohibited: { desc: 'Prevents registrar renewal requests', severity: 'caution' },
  clienthold: { desc: 'DNS is disabled by registrar; domain will not resolve', severity: 'critical' },
  servertransferprohibited: { desc: 'Registry-level lock preventing transfers', severity: 'normal' },
  serverdeleteprohibited: { desc: 'Registry-level lock preventing deletion', severity: 'normal' },
  serverupdateprohibited: { desc: 'Registry-level lock preventing updates', severity: 'normal' },
  serverrenewprohibited: { desc: 'Registry-level lock preventing renewals', severity: 'caution' },
  serverhold: { desc: 'Registry-suspended; domain will not resolve in DNS', severity: 'critical' },
  ok: { desc: 'Active domain with no special operational restrictions', severity: 'normal' },
  active: { desc: 'Domain is active in registry', severity: 'normal' },
  redemptionperiod: { desc: 'Expired domain held before release for deletion', severity: 'critical' },
  pendingdelete: { desc: 'Domain is pending purge from registry root', severity: 'critical' },
  pendingtransfer: { desc: 'Transfer to another registrar is in progress', severity: 'caution' },
  pendingupdate: { desc: 'Update request is being processed by registry', severity: 'caution' },
  pendingcreate: { desc: 'Domain registration is processing at registry', severity: 'caution' },
  addperiod: { desc: 'Grace period immediately following initial registration', severity: 'normal' },
  autorenewperiod: { desc: 'Automatic renewal grace period', severity: 'normal' },
  renewperiod: { desc: 'Registrar explicit renewal grace period', severity: 'normal' },
  transferperiod: { desc: 'Post-transfer grace period', severity: 'normal' },
};

function normalizeString(val?: string | null): string {
  return (val || '').trim().toLowerCase();
}

function normalizeArray(arr?: string[] | null): string[] {
  if (!arr || !Array.isArray(arr)) return [];
  return Array.from(new Set(arr.map((s) => String(s).trim().toLowerCase()).filter(Boolean))).sort();
}

export function compareValues(
  valA: string | string[] | null | undefined,
  valB: string | string[] | null | undefined
): DiffStatus {
  const isArrA = Array.isArray(valA);
  const isArrB = Array.isArray(valB);

  if (isArrA || isArrB) {
    const listA = normalizeArray(isArrA ? (valA as string[]) : valA ? [String(valA)] : []);
    const listB = normalizeArray(isArrB ? (valB as string[]) : valB ? [String(valB)] : []);

    if (listA.length === 0 && listB.length === 0) return 'MATCH';
    if (listA.length === 0 && listB.length > 0) return 'ONLY_B';
    if (listA.length > 0 && listB.length === 0) return 'ONLY_A';

    if (listA.length === listB.length && listA.every((v, i) => v === listB[i])) {
      return 'MATCH';
    }
    return 'DIFF';
  }

  const strA = normalizeString(valA as string);
  const strB = normalizeString(valB as string);

  if (!strA && !strB) return 'MATCH';
  if (!strA && strB) return 'ONLY_B';
  if (strA && !strB) return 'ONLY_A';
  return strA === strB ? 'MATCH' : 'DIFF';
}

function formatUtcPrecision(isoStr?: string): string {
  if (!isoStr) return 'Unknown';
  const ts = parseFlexibleDateMs(isoStr);
  if (ts === null || isNaN(ts)) return isoStr;
  const iso = new Date(ts).toISOString();
  if (iso.endsWith('T00:00:00.000Z')) {
    return iso.slice(0, 10);
  }
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
}

function formatExactDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return `${mins}m ${seconds % 60}s`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h ${mins % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days.toLocaleString()}d ${hours % 24}h`;
}

const GENERIC_SOA_RNAMES = new Set([
  'dns@cloudflare.com',
  'hostmaster@nsone.net',
  'awsdns-hostmaster@amazon.com',
  'cloud-dns-hostmaster@google.com',
  'msnhst@microsoft.com',
  'dns@jomax.net',
  'hostmaster@registrar-servers.com',
]);

function extractDkimTenantBase(target: string): string {
  const lower = target.toLowerCase();
  if (lower.endsWith('.onmicrosoft.com')) {
    const parts = lower.split('._domainkey.');
    return parts[1] || lower;
  }
  if (lower.includes('.wl.sendgrid.net')) {
    const match = lower.match(/(u\d+\.wl\.sendgrid\.net)/);
    return match ? match[1] : lower;
  }
  return extractApexDomain(lower) || lower;
}

export function computeWhoisDiff(domainA: WhoisDomainRecord, domainB: WhoisDomainRecord): WhoisDiffResult {
  const fieldDiffs: FieldDiffItem[] = [];

  // ==========================================
  // 1. CORPORATE & ATTRIBUTION (REVERSE WHOIS PIVOTS)
  // ==========================================

  // Registrant Org
  fieldDiffs.push({
    id: 'registrant_org',
    category: 'attribution',
    label: 'Registrant Organization',
    rfcOrSpec: 'RDAP / WHOIS',
    valueA: domainA.registrantOrg || 'Redacted for Privacy / Proxy',
    valueB: domainB.registrantOrg || 'Redacted for Privacy / Proxy',
    status: compareValues(domainA.registrantOrg, domainB.registrantOrg),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: true,
  });

  // Verification Tokens (Google, Microsoft, Atlassian, Apple, Stripe, etc.)
  const tokensA = (domainA.verificationTokens || []).map((t) => `${t.provider}: ${t.token}`);
  const tokensB = (domainB.verificationTokens || []).map((t) => `${t.provider}: ${t.token}`);
  const setTokB = new Set((domainA.verificationTokens || []).map((t) => t.token));
  const sharedTokens = (domainB.verificationTokens || []).filter((t) => setTokB.has(t.token));

  fieldDiffs.push({
    id: 'verification_tokens',
    category: 'attribution',
    label: 'Domain Verification Tokens (TXT)',
    rfcOrSpec: 'RFC 1464 / Cloud IDP',
    valueA: tokensA.length > 0 ? tokensA : ['No third-party verification tokens detected'],
    valueB: tokensB.length > 0 ? tokensB : ['No third-party verification tokens detected'],
    status: compareValues(tokensA, tokensB),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: true,
    deltaSummary:
      sharedTokens.length > 0
        ? `ATTRIBUTION MATCH: ${sharedTokens.length} identical verification token(s) shared!`
        : tokensA.length > 0 || tokensB.length > 0
        ? 'Divergent third-party service verification fingerprints'
        : 'No third-party services registered in DNS',
  });

  // SPF Email Infrastructure & Relays
  const spfIncludesA = domainA.spfIncludes || [];
  const spfIncludesB = domainB.spfIncludes || [];
  const sharedSpf = spfIncludesA.filter((inc) => spfIncludesB.includes(inc));

  fieldDiffs.push({
    id: 'spf_relays',
    category: 'attribution',
    label: 'Authorized Mail Relays (SPF)',
    rfcOrSpec: 'RFC 7208 SPF',
    valueA: spfIncludesA.length > 0 ? spfIncludesA : [domainA.spfRecord || 'No SPF record'],
    valueB: spfIncludesB.length > 0 ? spfIncludesB : [domainB.spfRecord || 'No SPF record'],
    status: compareValues(spfIncludesA, spfIncludesB),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: true,
    deltaSummary:
      sharedSpf.length > 0
        ? `SHARED MAIL GATEWAYS: ${sharedSpf.join(', ')}`
        : 'Separate authorized mail infrastructure',
  });

  // SPF Direct IP / Origin Mechanisms (ip4:, ip6:, a:, mx:, redirect=)
  const spfIpsA = domainA.spfIpMechanisms || [];
  const spfIpsB = domainB.spfIpMechanisms || [];
  const sharedSpfIps = spfIpsA.filter((ip) =>
    spfIpsB.some((b) => b.toLowerCase() === ip.toLowerCase())
  );

  if (spfIpsA.length > 0 || spfIpsB.length > 0) {
    fieldDiffs.push({
      id: 'spf_ip_leaks',
      category: 'attribution',
      label: 'SPF Origin IPs & Direct Mechanisms',
      rfcOrSpec: 'RFC 7208 ip4/ip6/redirect',
      valueA: spfIpsA.length > 0 ? spfIpsA : ['None specified'],
      valueB: spfIpsB.length > 0 ? spfIpsB : ['None specified'],
      status: compareValues(spfIpsA, spfIpsB),
      impactLevel: 'high',
      isLowImpact: false,
      isAttributionPivot: true,
      deltaSummary:
        sharedSpfIps.length > 0
          ? `SHARED SPF ORIGIN LEAK: ${sharedSpfIps.join(', ')}`
          : 'Distinct SPF direct IP mechanisms',
    });
  }

  // DMARC Policy, RUA & RUF Forensic Reporting
  const dmarcRuaMatch = Boolean(
    domainA.dmarcRua &&
      domainB.dmarcRua &&
      normalizeString(domainA.dmarcRua) === normalizeString(domainB.dmarcRua)
  );
  const dmarcRufMatch = Boolean(
    domainA.dmarcRuf &&
      domainB.dmarcRuf &&
      normalizeString(domainA.dmarcRuf) === normalizeString(domainB.dmarcRuf)
  );

  if (
    domainA.dmarcRua ||
    domainB.dmarcRua ||
    domainA.dmarcRuf ||
    domainB.dmarcRuf ||
    domainA.dmarcPolicy ||
    domainB.dmarcPolicy
  ) {
    const formatDmarc = (d: WhoisDomainRecord) => {
      if (!d.dmarcPolicy && !d.dmarcRua && !d.dmarcRuf) return 'No DMARC Record';
      const parts: string[] = [];
      if (d.dmarcPolicy) parts.push(`p=${d.dmarcPolicy}`);
      if (d.dmarcRua) parts.push(`rua=${d.dmarcRua}`);
      if (d.dmarcRuf) parts.push(`ruf=${d.dmarcRuf}`);
      return parts.join(' | ');
    };

    fieldDiffs.push({
      id: 'dmarc_policy',
      category: 'attribution',
      label: 'DMARC Policy & Aggregate / Forensic URIs',
      rfcOrSpec: 'RFC 7489 DMARC (rua / ruf)',
      valueA: formatDmarc(domainA),
      valueB: formatDmarc(domainB),
      status: compareValues(
        domainA.dmarcRuf || domainA.dmarcRua || domainA.dmarcPolicy,
        domainB.dmarcRuf || domainB.dmarcRua || domainB.dmarcPolicy
      ),
      impactLevel: domainA.dmarcRua || domainB.dmarcRua || domainA.dmarcRuf || domainB.dmarcRuf ? 'high' : 'medium',
      isLowImpact: false,
      isAttributionPivot: Boolean(
        (domainA.dmarcRua && domainB.dmarcRua) || (domainA.dmarcRuf && domainB.dmarcRuf)
      ),
      deltaSummary: dmarcRuaMatch || dmarcRufMatch ? 'SHARED DMARC REPORTING DESTINATION' : undefined,
    });
  }

  // DKIM Selectors & CNAME Tenant Delegations
  const dkimA = domainA.dkimSelectors || [];
  const dkimB = domainB.dkimSelectors || [];
  const dkimCnamesA = domainA.dkimCnames || [];
  const dkimCnamesB = domainB.dkimCnames || [];
  const dkimTenantsA = dkimCnamesA.map(extractDkimTenantBase);
  const dkimTenantsB = dkimCnamesB.map(extractDkimTenantBase);
  const sharedDkimTargets = Array.from(
    new Set(dkimTenantsA.filter((t) => dkimTenantsB.includes(t)))
  );

  if (dkimA.length > 0 || dkimB.length > 0) {
    fieldDiffs.push({
      id: 'dkim_selectors',
      category: 'attribution',
      label: 'DKIM Selectors & CNAME Tenants',
      rfcOrSpec: 'RFC 6376 _domainkey',
      valueA: dkimA.length > 0 ? dkimA : ['No common DKIM selectors detected'],
      valueB: dkimB.length > 0 ? dkimB : ['No common DKIM selectors detected'],
      status: compareValues(dkimA, dkimB),
      impactLevel: 'high',
      isLowImpact: false,
      isAttributionPivot: true,
      deltaSummary:
        sharedDkimTargets.length > 0
          ? `SHARED DKIM TENANT DELEGATION: ${sharedDkimTargets.join(', ')}`
          : undefined,
    });
  }

  // SOA Hostmaster Contact (RNAME)
  const sameSoaRname = Boolean(
    domainA.soaRname &&
      domainB.soaRname &&
      normalizeString(domainA.soaRname) === normalizeString(domainB.soaRname)
  );
  if (domainA.soaRname || domainB.soaRname) {
    fieldDiffs.push({
      id: 'soa_rname',
      category: 'attribution',
      label: 'SOA Hostmaster Contact (RNAME)',
      rfcOrSpec: 'RFC 1035 SOA RNAME',
      valueA: domainA.soaRname || 'Not resolved',
      valueB: domainB.soaRname || 'Not resolved',
      status: compareValues(domainA.soaRname, domainB.soaRname),
      impactLevel: 'high',
      isLowImpact: false,
      isAttributionPivot: true,
      deltaSummary: sameSoaRname
        ? GENERIC_SOA_RNAMES.has(normalizeString(domainA.soaRname))
          ? 'Shared managed DNS hostmaster'
          : `CUSTOM HOSTMASTER MATCH: ${domainA.soaRname}`
        : undefined,
    });
  }

  // Registrant Geography
  fieldDiffs.push({
    id: 'registrant_country',
    category: 'attribution',
    label: 'Registrant Country / State',
    rfcOrSpec: 'ISO 3166-1 / ISO 3166-2',
    valueA: domainA.registrantCountry ? `${domainA.registrantCountry.toUpperCase()}${domainA.registrantState ? ` (${domainA.registrantState})` : ''}` : 'Redacted / Not Disclosed',
    valueB: domainB.registrantCountry ? `${domainB.registrantCountry.toUpperCase()}${domainB.registrantState ? ` (${domainB.registrantState})` : ''}` : 'Redacted / Not Disclosed',
    status: compareValues(domainA.registrantCountry, domainB.registrantCountry),
    impactLevel: 'medium',
    isLowImpact: false,
  });

  // ==========================================
  // 2. CERTIFICATE TRANSPARENCY & LIVE TLS
  // ==========================================

  // Live TLS Subject Org & Common Name
  fieldDiffs.push({
    id: 'tls_subject_org',
    category: 'certificates',
    label: 'SSL/TLS Subject Organization',
    rfcOrSpec: 'RFC 5280 X.509',
    valueA: domainA.tlsSubjectOrg ? `${domainA.tlsSubjectOrg} (${domainA.tlsSubjectCn || domainA.domainName})` : domainA.tlsSubjectCn || 'Domain Validation (DV Only)',
    valueB: domainB.tlsSubjectOrg ? `${domainB.tlsSubjectOrg} (${domainB.tlsSubjectCn || domainB.domainName})` : domainB.tlsSubjectCn || 'Domain Validation (DV Only)',
    status: compareValues(domainA.tlsSubjectOrg || domainA.tlsSubjectCn, domainB.tlsSubjectOrg || domainB.tlsSubjectCn),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: Boolean(domainA.tlsSubjectOrg && domainB.tlsSubjectOrg),
  });

  // Live TLS Issuer CA
  fieldDiffs.push({
    id: 'tls_issuer_ca',
    category: 'certificates',
    label: 'SSL/TLS Certificate Authority',
    rfcOrSpec: 'RFC 5280 CA Hierarchy',
    valueA: domainA.tlsIssuerOrg ? `${domainA.tlsIssuerOrg}${domainA.tlsIssuerCn ? ` [${domainA.tlsIssuerCn}]` : ''}` : 'Probe Unresolved',
    valueB: domainB.tlsIssuerOrg ? `${domainB.tlsIssuerOrg}${domainB.tlsIssuerCn ? ` [${domainB.tlsIssuerCn}]` : ''}` : 'Probe Unresolved',
    status: compareValues(domainA.tlsIssuerOrg, domainB.tlsIssuerOrg),
    impactLevel: 'medium',
    isLowImpact: false,
  });

  // TLS Handshake Protocol & Cipher
  if (domainA.tlsProtocol || domainB.tlsProtocol) {
    fieldDiffs.push({
      id: 'tls_protocol',
      category: 'certificates',
      label: 'Negotiated TLS Protocol & Cipher',
      rfcOrSpec: 'RFC 8446 TLS 1.3',
      valueA: domainA.tlsProtocol ? `${domainA.tlsProtocol} (${domainA.tlsCipher || 'Default Cipher'})` : 'Connection Failed',
      valueB: domainB.tlsProtocol ? `${domainB.tlsProtocol} (${domainB.tlsCipher || 'Default Cipher'})` : 'Connection Failed',
      status: compareValues(domainA.tlsProtocol, domainB.tlsProtocol),
      impactLevel: 'medium',
      isLowImpact: false,
    });
  }

  // Certificate Transparency (crt.name / crt.sh) Subdomains
  const sampleA = domainA.crtSubdomainsSample || [];
  const sampleB = domainB.crtSubdomainsSample || [];
  const setSubsB = new Set(sampleB.map((s) => s.split('.')[0].toLowerCase()));
  const sharedSubs = sampleA
    .map((s) => s.split('.')[0].toLowerCase())
    .filter((prefix) => prefix !== domainA.rootDomain.split('.')[0] && setSubsB.has(prefix));
  const uniqueSharedSubs = Array.from(new Set(sharedSubs)).slice(0, 10);

  fieldDiffs.push({
    id: 'crt_subdomains_count',
    category: 'certificates',
    label: 'Certificate Transparency Subdomains',
    rfcOrSpec: 'RFC 6962 CT Logs / crt.name',
    valueA: `${domainA.crtSubdomainsCount?.toLocaleString() || 0} subdomains discovered${domainA.crtWildcardFound ? ' [Wildcard *. cert]' : ''}`,
    valueB: `${domainB.crtSubdomainsCount?.toLocaleString() || 0} subdomains discovered${domainB.crtWildcardFound ? ' [Wildcard *. cert]' : ''}`,
    status:
      domainA.crtSubdomainsCount === domainB.crtSubdomainsCount
        ? 'MATCH'
        : 'DIFF',
    impactLevel: 'high',
    isLowImpact: false,
    deltaSummary:
      uniqueSharedSubs.length > 0
        ? `COMMON SUBDOMAIN NAMING: ${uniqueSharedSubs.join(', ')}`
        : undefined,
  });

  // ==========================================
  // 3. NETWORK & BGP HOSTING (REVERSE IP / ASN)
  // ==========================================

  // BGP Autonomous System (ASN)
  const asnStrA = domainA.asn ? `${domainA.asn}${domainA.asnName ? ` (${domainA.asnName})` : ''}` : 'Unrouted / Private';
  const asnStrB = domainB.asn ? `${domainB.asn}${domainB.asnName ? ` (${domainB.asnName})` : ''}` : 'Unrouted / Private';
  const sameAsn = Boolean(domainA.asn && domainB.asn && domainA.asn === domainB.asn);

  fieldDiffs.push({
    id: 'bgp_asn',
    category: 'network',
    label: 'Autonomous System (BGP ASN)',
    rfcOrSpec: 'RFC 1930 / Team Cymru BGP',
    valueA: asnStrA,
    valueB: asnStrB,
    status: compareValues(domainA.asn, domainB.asn),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: sameAsn,
    deltaSummary: sameAsn ? 'SHARED HOSTING NETWORK (Same Autonomous System)' : 'Separate upstream network providers',
  });

  // Subnet /24 IP Collision
  const sameSubnet = Boolean(domainA.subnet24 && domainB.subnet24 && domainA.subnet24 === domainB.subnet24);
  fieldDiffs.push({
    id: 'subnet_24',
    category: 'network',
    label: 'IPv4 /24 Subnet Allocation',
    rfcOrSpec: 'CIDR Routing Prefix',
    valueA: domainA.subnet24 || 'None resolved',
    valueB: domainB.subnet24 || 'None resolved',
    status: compareValues(domainA.subnet24, domainB.subnet24),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: sameSubnet,
    deltaSummary: sameSubnet ? 'COLLISION: Co-located inside the same /24 IP subnet!' : undefined,
  });

  // IPv4 Records
  fieldDiffs.push({
    id: 'a_records',
    category: 'network',
    label: 'IPv4 Addresses (A Records)',
    rfcOrSpec: 'RFC 1035 A',
    valueA: domainA.aRecords?.length ? domainA.aRecords : ['None resolved'],
    valueB: domainB.aRecords?.length ? domainB.aRecords : ['None resolved'],
    status: compareValues(domainA.aRecords, domainB.aRecords),
    impactLevel: 'medium',
    isLowImpact: false,
  });

  // Reverse DNS (PTR)
  const ptrA = domainA.ptrRecords || [];
  const ptrB = domainB.ptrRecords || [];
  const ptrHostsA = domainA.ptrHostnames || [];
  const ptrHostsB = domainB.ptrHostnames || [];
  const sharedPtrHostnames = ptrHostsA.filter((h) => ptrHostsB.includes(h));

  if (ptrA.length > 0 || ptrB.length > 0) {
    fieldDiffs.push({
      id: 'ptr_records',
      category: 'network',
      label: 'Reverse DNS (PTR Hostnames)',
      rfcOrSpec: 'RFC 1035 / RFC 3596 PTR',
      valueA: ptrA.length > 0 ? ptrA : ['No PTR record'],
      valueB: ptrB.length > 0 ? ptrB : ['No PTR record'],
      status: compareValues(ptrHostsA, ptrHostsB),
      impactLevel: 'high',
      isLowImpact: false,
      isAttributionPivot: sharedPtrHostnames.length > 0,
      deltaSummary:
        sharedPtrHostnames.length > 0
          ? `IDENTICAL PTR HOSTNAME: ${sharedPtrHostnames.join(', ')}`
          : undefined,
    });
  }

  // Web Server software
  if (domainA.httpWebServer || domainB.httpWebServer) {
    fieldDiffs.push({
      id: 'web_server',
      category: 'network',
      label: 'Edge Web Server Technology',
      rfcOrSpec: 'RFC 9110 HTTP Server Header',
      valueA: domainA.httpWebServer ? `${domainA.httpWebServer} (HTTP ${domainA.httpStatusCode || 200})` : 'Undisclosed / Hidden',
      valueB: domainB.httpWebServer ? `${domainB.httpWebServer} (HTTP ${domainB.httpStatusCode || 200})` : 'Undisclosed / Hidden',
      status: compareValues(domainA.httpWebServer, domainB.httpWebServer),
      impactLevel: 'medium',
      isLowImpact: false,
    });
  }

  // ==========================================
  // 4. DNS & MAIL INFRASTRUCTURE
  // ==========================================

  // DNS Provider
  const dnsProvA = domainA.dnsProvider || inferDnsProvider(domainA.nameservers);
  const dnsProvB = domainB.dnsProvider || inferDnsProvider(domainB.nameservers);
  fieldDiffs.push({
    id: 'dns_provider',
    category: 'infrastructure',
    label: 'Managed DNS Provider',
    rfcOrSpec: 'Inferred via NS Cluster',
    valueA: dnsProvA,
    valueB: dnsProvB,
    status: compareValues(dnsProvA, dnsProvB),
    impactLevel: 'high',
    isLowImpact: false,
  });

  // Authoritative Nameservers
  fieldDiffs.push({
    id: 'nameservers',
    category: 'infrastructure',
    label: 'Authoritative Nameservers',
    rfcOrSpec: 'RFC 1035 NS',
    valueA: domainA.nameservers.length > 0 ? domainA.nameservers : ['None listed'],
    valueB: domainB.nameservers.length > 0 ? domainB.nameservers : ['None listed'],
    status: compareValues(domainA.nameservers, domainB.nameservers),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: true,
  });

  // SOA Primary Master (MNAME)
  const sameSoaMname = Boolean(
    domainA.soaMname &&
      domainB.soaMname &&
      normalizeString(domainA.soaMname) === normalizeString(domainB.soaMname)
  );
  if (domainA.soaMname || domainB.soaMname) {
    fieldDiffs.push({
      id: 'soa_mname',
      category: 'infrastructure',
      label: 'SOA Primary Master (MNAME)',
      rfcOrSpec: 'RFC 1035 SOA MNAME',
      valueA: domainA.soaMname ? `${domainA.soaMname}${domainA.soaSerial ? ` (serial ${domainA.soaSerial})` : ''}` : 'Not resolved',
      valueB: domainB.soaMname ? `${domainB.soaMname}${domainB.soaSerial ? ` (serial ${domainB.soaSerial})` : ''}` : 'Not resolved',
      status: compareValues(domainA.soaMname, domainB.soaMname),
      impactLevel: 'medium',
      isLowImpact: false,
      isAttributionPivot: sameSoaMname,
    });
  }

  // Mail Provider (MX)
  const mailProvA = domainA.mailProvider || 'No MX Records';
  const mailProvB = domainB.mailProvider || 'No MX Records';
  fieldDiffs.push({
    id: 'mail_provider',
    category: 'infrastructure',
    label: 'Enterprise Mail Solution',
    rfcOrSpec: 'RFC 5321 MX Exchange',
    valueA: mailProvA,
    valueB: mailProvB,
    status: compareValues(mailProvA, mailProvB),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: mailProvA !== 'No MX Records' && mailProvA !== 'No MX Records Listed' && mailProvA === mailProvB,
  });

  // DNSSEC
  fieldDiffs.push({
    id: 'dnssec',
    category: 'security',
    label: 'DNSSEC Cryptographic Signing',
    rfcOrSpec: 'RFC 4033 / 4034',
    valueA: domainA.dnssec.toUpperCase(),
    valueB: domainB.dnssec.toUpperCase(),
    status: compareValues(domainA.dnssec, domainB.dnssec),
    impactLevel: 'medium',
    isLowImpact: false,
  });

  // DNSSEC Key Tags & DS Digests
  const dsA = domainA.dsRecords || [];
  const dsB = domainB.dsRecords || [];
  const dnskeyA = domainA.dnskeyRecords || [];
  const dnskeyB = domainB.dnskeyRecords || [];
  const keysA = [...dsA.map((d) => `DS: ${d}`), ...dnskeyA.map((k) => `DNSKEY: ${k}`)];
  const keysB = [...dsB.map((d) => `DS: ${d}`), ...dnskeyB.map((k) => `DNSKEY: ${k}`)];

  if (keysA.length > 0 || keysB.length > 0) {
    fieldDiffs.push({
      id: 'dnssec_keys',
      category: 'security',
      label: 'DNSSEC DS & DNSKEY Material',
      rfcOrSpec: 'RFC 4034 DS / DNSKEY',
      valueA: keysA.length > 0 ? keysA : ['Unsigned / No DS or DNSKEY'],
      valueB: keysB.length > 0 ? keysB : ['Unsigned / No DS or DNSKEY'],
      status: compareValues(keysA, keysB),
      impactLevel: 'medium',
      isLowImpact: false,
    });
  }

  // CAA Records & Incident Contact (iodef)
  const caaA = domainA.caaRecords || [];
  const caaB = domainB.caaRecords || [];
  const caaIodefA = domainA.caaIodef || [];
  const caaIodefB = domainB.caaIodef || [];
  const sharedCaaIodef = caaIodefA.filter((u) =>
    caaIodefB.some((b) => normalizeString(b) === normalizeString(u))
  );

  if (caaA.length > 0 || caaB.length > 0) {
    fieldDiffs.push({
      id: 'caa_records',
      category: 'security',
      label: 'CAA Certificate Policies & IODEF',
      rfcOrSpec: 'RFC 8659 CAA',
      valueA: caaA.length > 0 ? caaA : ['No CAA restriction'],
      valueB: caaB.length > 0 ? caaB : ['No CAA restriction'],
      status: compareValues(caaA, caaB),
      impactLevel: sharedCaaIodef.length > 0 ? 'high' : 'medium',
      isLowImpact: false,
      isAttributionPivot: sharedCaaIodef.length > 0,
      deltaSummary:
        sharedCaaIodef.length > 0
          ? `SHARED CAA IODEF CONTACT: ${sharedCaaIodef.join(', ')}`
          : undefined,
    });
  }

  // ==========================================
  // 5. REGISTRAR & EPP SECURITY
  // ==========================================

  // Sponsoring Registrar
  fieldDiffs.push({
    id: 'registrar_name',
    category: 'registrar',
    label: 'Sponsoring Registrar',
    rfcOrSpec: 'ICANN RAA',
    valueA: domainA.registrar || 'Protected / Redacted',
    valueB: domainB.registrar || 'Protected / Redacted',
    status: compareValues(domainA.registrar, domainB.registrar),
    impactLevel: 'high',
    isLowImpact: false,
    isAttributionPivot: Boolean(domainA.registrar && domainB.registrar && domainA.registrar === domainB.registrar),
  });

  // EPP Domain Status Flags
  fieldDiffs.push({
    id: 'epp_status',
    category: 'security',
    label: 'EPP Domain Status Locks',
    rfcOrSpec: 'RFC 5731 EPP',
    valueA: domainA.status.length > 0 ? domainA.status : ['ok (unlocked)'],
    valueB: domainB.status.length > 0 ? domainB.status : ['ok (unlocked)'],
    status: compareValues(domainA.status, domainB.status),
    impactLevel: 'high',
    isLowImpact: false,
  });

  // Abuse Contact Email
  fieldDiffs.push({
    id: 'abuse_email',
    category: 'registrar',
    label: 'Registrar Abuse Contact',
    rfcOrSpec: 'RFC 2142',
    valueA: domainA.abuseContactEmail || 'Protected / Registry Proxy',
    valueB: domainB.abuseContactEmail || 'Protected / Registry Proxy',
    status: compareValues(domainA.abuseContactEmail, domainB.abuseContactEmail),
    impactLevel: 'medium',
    isLowImpact: false,
  });

  // ==========================================
  // 6. LIFECYCLE & DATES (WITH LOW-IMPACT FILTERING)
  // ==========================================

  // Domain Age & Creation Date
  const ageDeltaYears =
    domainA.domainAgeYears && domainB.domainAgeYears
      ? Math.abs(domainA.domainAgeYears - domainB.domainAgeYears)
      : undefined;
  const isSignificantAgeDiscrepancy = ageDeltaYears !== undefined && ageDeltaYears >= 1.0;

  fieldDiffs.push({
    id: 'domain_age',
    category: 'lifecycle',
    label: 'Domain Age & Inception',
    rfcOrSpec: 'Registry Creation Date',
    valueA: domainA.domainAgeFormatted || (domainA.domainAgeYears ? `${domainA.domainAgeYears} years` : 'Undetermined'),
    valueB: domainB.domainAgeFormatted || (domainB.domainAgeYears ? `${domainB.domainAgeYears} years` : 'Undetermined'),
    status:
      domainA.domainAgeYears && domainB.domainAgeYears
        ? ageDeltaYears !== undefined && ageDeltaYears < 0.1
          ? 'MATCH'
          : 'DIFF'
        : 'DIFF',
    impactLevel: isSignificantAgeDiscrepancy ? 'high' : 'low',
    isLowImpact: !isSignificantAgeDiscrepancy,
    deltaSummary:
      ageDeltaYears !== undefined
        ? isSignificantAgeDiscrepancy
          ? `SIGNIFICANT DISCREPANCY: ${ageDeltaYears.toFixed(1)} years apart`
          : `Minor difference (${Math.round(ageDeltaYears * 12)} months) — expected sibling spread`
        : undefined,
  });

  // Exact Timestamp Precision & Clustering (<= 24h)
  const createdTsA = parseDateToTimestamp(domainA.createdDate);
  const createdTsB = parseDateToTimestamp(domainB.createdDate);
  const updatedTsA = parseDateToTimestamp(domainA.updatedDate);
  const updatedTsB = parseDateToTimestamp(domainB.updatedDate);

  const createdDeltaSeconds =
    createdTsA !== null && createdTsB !== null
      ? Math.round(Math.abs(createdTsA - createdTsB) / 1000)
      : undefined;
  const updatedDeltaSeconds =
    updatedTsA !== null && updatedTsB !== null
      ? Math.round(Math.abs(updatedTsA - updatedTsB) / 1000)
      : undefined;

  const isCreationClustered = createdDeltaSeconds !== undefined && createdDeltaSeconds <= 86400;
  const isUpdateClustered = updatedDeltaSeconds !== undefined && updatedDeltaSeconds <= 86400;

  // Registration Date (Exact UTC ISO 8601)
  fieldDiffs.push({
    id: 'created_date',
    category: 'lifecycle',
    label: 'Registration Timestamp (UTC)',
    rfcOrSpec: 'ISO 8601 / RDAP Events',
    valueA: formatUtcPrecision(domainA.createdDate),
    valueB: formatUtcPrecision(domainB.createdDate),
    status: compareValues(domainA.createdDate, domainB.createdDate),
    impactLevel: isCreationClustered || isSignificantAgeDiscrepancy ? 'high' : 'low',
    isLowImpact: !isCreationClustered && !isSignificantAgeDiscrepancy,
    isAttributionPivot: isCreationClustered,
    deltaSummary:
      createdDeltaSeconds !== undefined
        ? isCreationClustered
          ? `CLUSTERED REGISTRATION: ${formatExactDuration(createdDeltaSeconds)} apart`
          : `${formatExactDuration(createdDeltaSeconds)} apart`
        : undefined,
  });

  if (createdDeltaSeconds !== undefined || updatedDeltaSeconds !== undefined) {
    fieldDiffs.push({
      id: 'temporal_clustering',
      category: 'lifecycle',
      label: 'Timestamp Clustering (Reg / Mod)',
      rfcOrSpec: 'RDAP Event Delta',
      valueA: [
        `Created: ${formatUtcPrecision(domainA.createdDate)}`,
        `Updated: ${formatUtcPrecision(domainA.updatedDate)}`,
      ],
      valueB: [
        `Created: ${formatUtcPrecision(domainB.createdDate)}`,
        `Updated: ${formatUtcPrecision(domainB.updatedDate)}`,
      ],
      status: isCreationClustered || isUpdateClustered ? 'MATCH' : 'DIFF',
      impactLevel: isCreationClustered || isUpdateClustered ? 'high' : 'low',
      isLowImpact: !isCreationClustered && !isUpdateClustered,
      isAttributionPivot: isCreationClustered || isUpdateClustered,
      deltaSummary: [
        createdDeltaSeconds !== undefined
          ? `Creation gap: ${formatExactDuration(createdDeltaSeconds)}${isCreationClustered ? ' [CLUSTERED <= 24H]' : ''}`
          : null,
        updatedDeltaSeconds !== undefined
          ? `Update gap: ${formatExactDuration(updatedDeltaSeconds)}${isUpdateClustered ? ' [SYNCHRONIZED <= 24H]' : ''}`
          : null,
      ]
        .filter(Boolean)
        .join(' | '),
    });
  }

  // Time Until Expiration
  const expDaysDelta =
    domainA.daysUntilExpiration !== undefined && domainB.daysUntilExpiration !== undefined
      ? Math.abs(domainA.daysUntilExpiration - domainB.daysUntilExpiration)
      : undefined;
  const isSignificantExpDiscrepancy =
    (expDaysDelta !== undefined && expDaysDelta > 180) ||
    (domainA.expirationStatus !== undefined && domainA.expirationStatus !== domainB.expirationStatus);

  fieldDiffs.push({
    id: 'days_until_expiration',
    category: 'lifecycle',
    label: 'Registry Expiration Horizon',
    rfcOrSpec: 'Renewal Countdown',
    valueA:
      domainA.daysUntilExpiration !== undefined
        ? `${domainA.daysUntilExpiration.toLocaleString()} days (${domainA.expirationStatus?.toUpperCase()})`
        : 'Undetermined',
    valueB:
      domainB.daysUntilExpiration !== undefined
        ? `${domainB.daysUntilExpiration.toLocaleString()} days (${domainB.expirationStatus?.toUpperCase()})`
        : 'Undetermined',
    status: compareValues(domainA.expirationStatus, domainB.expirationStatus),
    impactLevel: isSignificantExpDiscrepancy ? 'high' : 'low',
    isLowImpact: !isSignificantExpDiscrepancy,
    deltaSummary:
      expDaysDelta !== undefined
        ? isSignificantExpDiscrepancy
          ? `SIGNIFICANT EXPIRATION GAP: ${expDaysDelta.toLocaleString()} days`
          : `Synchronized expiration window (${expDaysDelta} days gap)`
        : undefined,
  });

  // LOW IMPACT: Last Registry Update Timestamp (Hidden by default unless clustered)
  fieldDiffs.push({
    id: 'updated_date',
    category: 'lifecycle',
    label: 'Last Registry Touch / Update',
    rfcOrSpec: 'Automated Registry Sync',
    valueA: formatUtcPrecision(domainA.updatedDate),
    valueB: formatUtcPrecision(domainB.updatedDate),
    status: compareValues(domainA.updatedDate, domainB.updatedDate),
    impactLevel: isUpdateClustered ? 'medium' : 'low',
    isLowImpact: !isUpdateClustered,
    deltaSummary: isUpdateClustered
      ? `Registry updates within ${formatExactDuration(updatedDeltaSeconds!)}`
      : 'Routine registry sync timestamp (low analytical value)',
  });

  // LOW IMPACT: Registrar IANA ID Number
  fieldDiffs.push({
    id: 'iana_id',
    category: 'registrar',
    label: 'Registrar IANA ID Number',
    rfcOrSpec: 'IANA Registry',
    valueA: domainA.ianaId ? `ID #${domainA.ianaId}` : 'Not Specified',
    valueB: domainB.ianaId ? `ID #${domainB.ianaId}` : 'Not Specified',
    status: compareValues(domainA.ianaId, domainB.ianaId),
    impactLevel: 'low',
    isLowImpact: true,
  });

  // ==========================================
  // ATTRIBUTION LINKAGE ASSESSMENT & VERDICT
  // ==========================================
  const linkages: SharedLinkageInsight[] = [];

  if (sharedTokens.length > 0) {
    linkages.push({
      type: 'attribution',
      title: 'Shared Verification Fingerprints',
      description: `Domains share ${sharedTokens.length} identical verification token(s) (${sharedTokens.map((t) => t.provider).join(', ')}). High certainty of identical administrative account.`,
      strength: 'definitive',
    });
  }

  if (sameSubnet) {
    linkages.push({
      type: 'network',
      title: 'Co-Located Subnet /24',
      description: `Both domains resolve to the identical /24 network subnet (${domainA.subnet24}).`,
      strength: 'strong',
    });
  }

  if (sameAsn && domainA.asn) {
    linkages.push({
      type: 'network',
      title: 'Shared BGP Autonomous System',
      description: `Both targets are routed through ${domainA.asn} (${domainA.asnName || 'Same AS Org'}).`,
      strength: 'moderate',
    });
  }

  // Shared NS
  const setNsA = new Set(domainA.nameservers.map((s) => s.toLowerCase()));
  const setNsB = new Set(domainB.nameservers.map((s) => s.toLowerCase()));
  const sharedNs = [...setNsA].filter((ns) => setNsB.has(ns));
  const unionNs = new Set([...setNsA, ...setNsB]);

  if (sharedNs.length > 0) {
    linkages.push({
      type: 'infrastructure',
      title: 'Shared Authoritative Nameservers',
      description: `Domains share ${sharedNs.length} nameserver hostname(s) (${sharedNs.slice(0, 2).join(', ')}).`,
      strength: 'strong',
    });
  }

  if (domainA.tlsSubjectOrg && domainB.tlsSubjectOrg && normalizeString(domainA.tlsSubjectOrg) === normalizeString(domainB.tlsSubjectOrg)) {
    linkages.push({
      type: 'certificates',
      title: 'Matching SSL Subject Organization',
      description: `Both SSL certificates are issued directly to "${domainA.tlsSubjectOrg}".`,
      strength: 'definitive',
    });
  }

  if (mailProvA !== 'No MX Records Listed' && mailProvA !== 'No MX Records' && mailProvA === mailProvB) {
    linkages.push({
      type: 'infrastructure',
      title: 'Identical Mail Provider',
      description: `Both domains employ ${mailProvA}.`,
      strength: 'moderate',
    });
  }

  if (sameSoaRname && domainA.soaRname) {
    const isGeneric = GENERIC_SOA_RNAMES.has(normalizeString(domainA.soaRname));
    linkages.push({
      type: 'attribution',
      title: isGeneric ? 'Shared Managed SOA Hostmaster' : 'Matching Custom SOA Hostmaster (RNAME)',
      description: `Both zones specify ${domainA.soaRname} as the authoritative SOA RNAME contact.`,
      strength: isGeneric ? 'weak' : 'strong',
    });
  }

  if (sharedSpfIps.length > 0) {
    linkages.push({
      type: 'network',
      title: 'Shared SPF Origin IP Mechanism',
      description: `Both SPF policies authorize identical direct IP/host mechanisms (${sharedSpfIps.join(', ')}).`,
      strength: 'strong',
    });
  }

  if (dmarcRuaMatch || dmarcRufMatch) {
    linkages.push({
      type: 'attribution',
      title: 'Shared DMARC Reporting Destination',
      description: `Both domains route DMARC reports to ${domainA.dmarcRuf || domainA.dmarcRua}.`,
      strength: 'strong',
    });
  }

  if (sharedDkimTargets.length > 0) {
    linkages.push({
      type: 'attribution',
      title: 'Shared DKIM CNAME Delegation Tenant',
      description: `DKIM selectors delegate to the same external tenant (${sharedDkimTargets.join(', ')}).`,
      strength: 'strong',
    });
  }

  if (sharedPtrHostnames.length > 0) {
    linkages.push({
      type: 'network',
      title: 'Identical Reverse DNS (PTR) Hostname',
      description: `Resolved IPs map to the exact same PTR hostname (${sharedPtrHostnames[0]}).`,
      strength: 'strong',
    });
  }

  if (isCreationClustered && createdDeltaSeconds !== undefined) {
    linkages.push({
      type: 'registrar',
      title: 'Clustered Registration Timestamp',
      description: `Both domains were registered within ${formatExactDuration(createdDeltaSeconds)} of each other.`,
      strength: 'strong',
    });
  }

  if (domainA.registrar && domainB.registrar && normalizeString(domainA.registrar) === normalizeString(domainB.registrar)) {
    linkages.push({
      type: 'registrar',
      title: 'Shared Sponsoring Registrar',
      description: `Both registered with ${domainA.registrar}.`,
      strength: 'moderate',
    });
  }

  // Overall attribution verdict
  let overallAttributionVerdict: 'CONFIRMED_SHARED_OWNERSHIP' | 'LIKELY_AFFILIATED' | 'SHARED_CLOUD_INFRASTRUCTURE' | 'DISTINCT_INDEPENDENT_ENTITIES' = 'DISTINCT_INDEPENDENT_ENTITIES';
  const hasDefinitive = linkages.some((l) => l.strength === 'definitive');
  const strongCount = linkages.filter((l) => l.strength === 'strong').length;

  if (hasDefinitive) {
    overallAttributionVerdict = 'CONFIRMED_SHARED_OWNERSHIP';
  } else if (strongCount >= 2 || (strongCount >= 1 && linkages.length >= 3)) {
    overallAttributionVerdict = 'LIKELY_AFFILIATED';
  } else if (sameAsn || (domainA.dnsProvider && domainA.dnsProvider === domainB.dnsProvider)) {
    overallAttributionVerdict = 'SHARED_CLOUD_INFRASTRUCTURE';
  } else {
    overallAttributionVerdict = 'DISTINCT_INDEPENDENT_ENTITIES';
  }

  const divergentCount = fieldDiffs.filter((f) => f.status === 'DIFF' || f.status === 'ONLY_A' || f.status === 'ONLY_B').length;
  const matchingCount = fieldDiffs.filter((f) => f.status === 'MATCH').length;
  const highImpactCount = fieldDiffs.filter((f) => f.impactLevel === 'high').length;
  const lowImpactCount = fieldDiffs.filter((f) => f.isLowImpact).length;

  const summary: WhoisDiffSummary = {
    totalFieldsCompared: fieldDiffs.length,
    divergentCount,
    matchingCount,
    highImpactCount,
    lowImpactCount,
    ageDeltaFormatted:
      ageDeltaYears !== undefined
        ? `${ageDeltaYears.toFixed(1)}y (${domainA.domainAgeYears! > domainB.domainAgeYears! ? domainA.domainName : domainB.domainName} older)`
        : undefined,
    expirationDeltaFormatted:
      expDaysDelta !== undefined
        ? `${expDaysDelta.toLocaleString()} days gap`
        : undefined,
    hasSignificantAgeDiscrepancy: isSignificantAgeDiscrepancy,
    hasSignificantExpirationDiscrepancy: isSignificantExpDiscrepancy,
    sharedNameserversCount: sharedNs.length,
    totalNameserversCount: unionNs.size,
    sharedEppCount: (domainA.status || []).filter((s) => (domainB.status || []).includes(s)).length,
    sameRegistrar: normalizeString(domainA.registrar) === normalizeString(domainB.registrar) && Boolean(domainA.registrar),
    sameDnsProvider: normalizeString(dnsProvA) === normalizeString(dnsProvB),
    sameMailProvider: mailProvA !== 'No MX Records Listed' && mailProvA !== 'No MX Records' && mailProvA === mailProvB,
    sameAsn,
    sameSubnet24: sameSubnet,
    sameTlsSubjectOrg: Boolean(domainA.tlsSubjectOrg && domainB.tlsSubjectOrg && normalizeString(domainA.tlsSubjectOrg) === normalizeString(domainB.tlsSubjectOrg)),
    sharedVerificationTokensCount: sharedTokens.length,
    sharedCtSubdomains: uniqueSharedSubs,
    sameSoaRname,
    sameSoaMname,
    sharedPtrHostnames,
    sharedSpfIps,
    sameDmarcRua: dmarcRuaMatch,
    sameDmarcRuf: dmarcRufMatch,
    sharedDkimTargets,
    createdDeltaSeconds,
    updatedDeltaSeconds,
    isCreationClustered,
    isUpdateClustered,
    linkages,
    overallAttributionVerdict,
  };

  const normalizedRawA = formatCanonicalJsonText(domainA.rawText || '');
  const normalizedRawB = formatCanonicalJsonText(domainB.rawText || '');
  const normalizedDomainA =
    normalizedRawA === (domainA.rawText || '') ? domainA : { ...domainA, rawText: normalizedRawA };
  const normalizedDomainB =
    normalizedRawB === (domainB.rawText || '') ? domainB : { ...domainB, rawText: normalizedRawB };

  const rawTextDiff = computeTextDiff(normalizedRawA, normalizedRawB, domainA.domainName, domainB.domainName);

  return {
    domainA: normalizedDomainA,
    domainB: normalizedDomainB,
    fieldDiffs,
    summary,
    rawTextDiff,
    computedAt: Date.now(),
  };
}

export function computeTextDiff(textA: string, textB: string, labelA = 'Domain A', labelB = 'Domain B'): TextDiffLine[] {
  const normalizedA = formatCanonicalJsonText(textA);
  const normalizedB = formatCanonicalJsonText(textB);
  const linesA = normalizedA.split(/\r?\n/).map((l) => l.trimEnd());
  const linesB = normalizedB.split(/\r?\n/).map((l) => l.trimEnd());

  const result: TextDiffLine[] = [];
  result.push({
    type: 'header',
    text: `--- ${labelA} (WHOIS / RDAP Record)`,
  });
  result.push({
    type: 'header',
    text: `+++ ${labelB} (WHOIS / RDAP Record)`,
  });

  // Trim common prefix and suffix to shrink LCS DP table
  let prefix = 0;
  while (prefix < linesA.length && prefix < linesB.length && linesA[prefix] === linesB[prefix]) {
    prefix++;
  }

  let suffix = 0;
  while (
    suffix < linesA.length - prefix &&
    suffix < linesB.length - prefix &&
    linesA[linesA.length - 1 - suffix] === linesB[linesB.length - 1 - suffix]
  ) {
    suffix++;
  }

  let lineANum = 1;
  let lineBNum = 1;

  for (let i = 0; i < prefix; i++) {
    result.push({ type: 'same', text: `  ${linesA[i]}`, lineA: lineANum++, lineB: lineBNum++ });
  }

  const midA = linesA.slice(prefix, linesA.length - suffix);
  const midB = linesB.slice(prefix, linesB.length - suffix);
  const m = midA.length;
  const n = midB.length;

  if (m === 0 && n === 0) {
    // Identical middle slice
  } else if (m === 0) {
    for (const b of midB) {
      result.push({ type: 'add', text: `+ ${b}`, lineB: lineBNum++ });
    }
  } else if (n === 0) {
    for (const a of midA) {
      result.push({ type: 'delete', text: `- ${a}`, lineA: lineANum++ });
    }
  } else if (m * n <= 1_500_000) {
    const cols = n + 1;
    const dp = new Int32Array((m + 1) * cols);

    for (let i = m - 1; i >= 0; i--) {
      const rowOffset = i * cols;
      const nextRowOffset = (i + 1) * cols;
      const line = midA[i];
      for (let j = n - 1; j >= 0; j--) {
        if (line === midB[j]) {
          dp[rowOffset + j] = dp[nextRowOffset + j + 1] + 1;
        } else {
          const down = dp[nextRowOffset + j];
          const right = dp[rowOffset + j + 1];
          dp[rowOffset + j] = down >= right ? down : right;
        }
      }
    }

    let i = 0;
    let j = 0;
    while (i < m && j < n) {
      if (midA[i] === midB[j]) {
        result.push({ type: 'same', text: `  ${midA[i]}`, lineA: lineANum++, lineB: lineBNum++ });
        i++;
        j++;
      } else if (dp[(i + 1) * cols + j] >= dp[i * cols + j + 1]) {
        result.push({ type: 'delete', text: `- ${midA[i]}`, lineA: lineANum++ });
        i++;
      } else {
        result.push({ type: 'add', text: `+ ${midB[j]}`, lineB: lineBNum++ });
        j++;
      }
    }
    while (i < m) {
      result.push({ type: 'delete', text: `- ${midA[i]}`, lineA: lineANum++ });
      i++;
    }
    while (j < n) {
      result.push({ type: 'add', text: `+ ${midB[j]}`, lineB: lineBNum++ });
      j++;
    }
  } else {
    for (const a of midA) {
      result.push({ type: 'delete', text: `- ${a}`, lineA: lineANum++ });
    }
    for (const b of midB) {
      result.push({ type: 'add', text: `+ ${b}`, lineB: lineBNum++ });
    }
  }

  for (let i = 0; i < suffix; i++) {
    const idxA = linesA.length - suffix + i;
    result.push({ type: 'same', text: `  ${linesA[idxA]}`, lineA: lineANum++, lineB: lineBNum++ });
  }

  return result.slice(0, 2000);
}

// Pure-Browser Authoritative RDAP + DoH + BGP/ASN + CT Subdomain Intelligence (GitHub Pages compatible)
const CLIENT_RDAP_TLD_MAP: Record<string, string> = {
  com: 'https://rdap.verisign.com/com/v1/domain/',
  net: 'https://rdap.verisign.com/net/v1/domain/',
  org: 'https://rdap.publicinterestregistry.org/rdap/domain/',
  dev: 'https://pubapi.registry.google/rdap/domain/',
  app: 'https://pubapi.registry.google/rdap/domain/',
  page: 'https://pubapi.registry.google/rdap/domain/',
  soy: 'https://pubapi.registry.google/rdap/domain/',
  how: 'https://pubapi.registry.google/rdap/domain/',
  io: 'https://rdap.identitydigital.services/rdap/domain/',
  info: 'https://rdap.identitydigital.services/rdap/domain/',
  pro: 'https://rdap.identitydigital.services/rdap/domain/',
  ca: 'https://rdap.ca.fury.ca/rdap/domain/',
  fr: 'https://rdap.nic.fr/domain/',
  nl: 'https://rdap.sidn.nl/domain/',
  cz: 'https://rdap.nic.cz/domain/',
  br: 'https://rdap.registro.br/domain/',
  ai: 'https://rdap.identitydigital.services/rdap/domain/',
};

let ianaBootstrapCachePromise: Promise<Record<string, string>> | null = null;
let backendApiAvailable: boolean | null = null;

function shouldUseBackendApi(): boolean {
  if (import.meta.env.VITE_STATIC_PAGES === 'true') {
    return false;
  }
  if (typeof window !== 'undefined') {
    const host = window.location.hostname.toLowerCase();
    if (host.endsWith('.github.io')) {
      return false;
    }
  }
  return backendApiAvailable !== false;
}

async function getIanaRdapBootstrapMap(): Promise<Record<string, string>> {
  if (!ianaBootstrapCachePromise) {
    ianaBootstrapCachePromise = (async () => {
      const map: Record<string, string> = { ...CLIENT_RDAP_TLD_MAP };
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const res = await fetch('https://data.iana.org/rdap/dns.json', {
          headers: { Accept: 'application/json' },
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data?.services)) {
            for (const entry of data.services) {
              if (!Array.isArray(entry) || entry.length < 2) continue;
              const tlds: string[] = entry[0];
              const urls: string[] = entry[1];
              const base = urls.find((u) => typeof u === 'string' && u.startsWith('https://')) || urls[0];
              if (!base) continue;
              const normalizedBase = base.endsWith('/') ? `${base}domain/` : `${base}/domain/`;
              for (const tld of tlds) {
                const cleanTld = String(tld).toLowerCase().trim();
                if (cleanTld && !CLIENT_RDAP_TLD_MAP[cleanTld]) {
                  map[cleanTld] = normalizedBase;
                }
              }
            }
          }
        }
      } catch {}
      return map;
    })();
  }
  return ianaBootstrapCachePromise;
}

function inferClientMailProvider(mxRecords: string[]): string {
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

async function lookupClientIpAsn(
  ip: string
): Promise<{ asn?: string; asnName?: string; bgpPrefix?: string; subnet24?: string }> {
  if (!ip || !ip.includes('.')) return {};
  const octets = ip.trim().split('.');
  if (octets.length !== 4 || octets.some((o) => !/^\d+$/.test(o))) return {};
  const subnet24 = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;

  // 1. Primary: Team Cymru ASN DNS TXT via DoH (CORS *)
  try {
    const rev = [...octets].reverse().join('.');
    const originRes = await queryBrowserDoh(`${rev}.origin.asn.cymru.com`, 'TXT', 3500);
    const rawTxt = (originRes.Answer || [])
      .filter((a) => a.type === 16 && a.data)
      .map((a) => a.data.replace(/^"+|"+$/g, '').replace(/"\s+"/g, ''))[0];
    if (rawTxt) {
      const parts = rawTxt.split('|').map((s) => s.trim());
      const rawAsn = (parts[0] || '').split(/\s+/)[0];
      const bgpPrefix = parts[1] || undefined;
      if (rawAsn && /^\d+$/.test(rawAsn)) {
        const asn = `AS${rawAsn}`;
        let asnName: string | undefined;
        try {
          const nameRes = await queryBrowserDoh(`${asn}.asn.cymru.com`, 'TXT', 3000);
          const nameTxt = (nameRes.Answer || [])
            .filter((a) => a.type === 16 && a.data)
            .map((a) => a.data.replace(/^"+|"+$/g, '').replace(/"\s+"/g, ''))[0];
          if (nameTxt) {
            const nparts = nameTxt.split('|').map((s) => s.trim());
            asnName = nparts[nparts.length - 1] || undefined;
          }
        } catch {}
        return { asn, asnName, bgpPrefix, subnet24 };
      }
    }
  } catch {}

  // 2. Fallback: RIPEstat network-info + ipwho.is (both CORS *)
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(
      `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`,
      { headers: { Accept: 'application/json' }, signal: controller.signal }
    );
    clearTimeout(timer);
    if (res.ok) {
      const json = await res.json();
      const rawAsn = Array.isArray(json?.data?.asns) ? json.data.asns[0] : undefined;
      const bgpPrefix = typeof json?.data?.prefix === 'string' ? json.data.prefix : undefined;
      if (rawAsn) {
        return {
          asn: `AS${String(rawAsn).replace(/^AS/i, '')}`,
          bgpPrefix,
          subnet24,
        };
      }
    }
  } catch {}

  return { subnet24 };
}

async function fetchClientCtSubdomains(rootDomain: string): Promise<{
  crtSubdomainsCount: number;
  crtSubdomainsSample: string[];
  crtWildcardFound: boolean;
}> {
  const cleanApex = (extractApexDomain(rootDomain) || rootDomain)
    .toLowerCase()
    .trim()
    .replace(/^\.+|\.+$/g, '');
  const subs = new Set<string>();
  let crtWildcardFound = false;

  const queryCertspotter = async () => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5500);
      const res = await fetch(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(cleanApex)}&include_subdomains=true&expand=dns_names`,
        { headers: { Accept: 'application/json' }, signal: controller.signal }
      );
      clearTimeout(timer);
      if (res.ok) {
        const items = await res.json();
        if (Array.isArray(items)) {
          for (const item of items) {
            if (!Array.isArray(item?.dns_names)) continue;
            for (const name of item.dns_names) {
              const cleaned = String(name).toLowerCase().trim().replace(/^\.+|\.+$/g, '');
              if (cleaned.startsWith('*.')) crtWildcardFound = true;
              const base = cleaned.startsWith('*.') ? cleaned.slice(2) : cleaned;
              if (base && (base === cleanApex || base.endsWith(`.${cleanApex}`))) {
                subs.add(cleaned);
              }
            }
          }
        }
      }
    } catch {}
  };

  const queryHackerTarget = async () => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(
        `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(cleanApex)}`,
        { signal: controller.signal }
      );
      clearTimeout(timer);
      if (res.ok) {
        const text = await res.text();
        if (text && !text.includes('error') && !text.includes('API count exceeded')) {
          for (const line of text.split('\n')) {
            const host = line.split(',')[0]?.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
            if (host && (host === cleanApex || host.endsWith(`.${cleanApex}`))) {
              subs.add(host);
            }
          }
        }
      }
    } catch {}
  };

  await Promise.all([queryCertspotter(), queryHackerTarget()]);
  const sorted = Array.from(subs).sort();
  return {
    crtSubdomainsCount: sorted.length,
    crtSubdomainsSample: sorted.slice(0, 120),
    crtWildcardFound,
  };
}

// Fallback Browser RDAP, DoH & OSINT Query (used on GitHub Pages static hosting or when backend is unavailable)
export async function fetchClientSideWhois(domain: string): Promise<WhoisDomainRecord> {
  const clean = sanitizeDomainInput(domain);
  const root = extractApexDomain(clean) || clean;
  const tld = root.split('.').pop() || '';

  let rdapData: any = null;
  let rawText = '';
  let registrar = 'Protected / Redacted';
  let ianaId: string | undefined;
  let createdDate: string | undefined;
  let updatedDate: string | undefined;
  let expiresDate: string | undefined;
  let abuseContactEmail: string | undefined;
  let registrantCountry: string | undefined;
  let registrantState: string | undefined;
  let registrantCity: string | undefined;
  let registrantOrg: string | undefined;
  const status: string[] = [];
  const nameservers: string[] = [];
  const aRecords: string[] = [];
  const aaaaRecords: string[] = [];
  const mxRecords: string[] = [];

  // Resolve RDAP endpoint from authoritative CORS-enabled IANA bootstrap + registry URLs
  const fetchRdap = async () => {
    const bootstrapMap = await getIanaRdapBootstrapMap();
    const candidateUrls: string[] = [];
    if (bootstrapMap[tld]) {
      candidateUrls.push(`${bootstrapMap[tld]}${encodeURIComponent(root)}`);
    }
    if (CLIENT_RDAP_TLD_MAP[tld]) {
      const directUrl = `${CLIENT_RDAP_TLD_MAP[tld]}${encodeURIComponent(root)}`;
      if (!candidateUrls.includes(directUrl)) candidateUrls.push(directUrl);
    }
    candidateUrls.push(`https://rdap.org/domain/${encodeURIComponent(root)}`);

    for (const url of candidateUrls) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 6500);
        const res = await fetch(url, {
          headers: { Accept: 'application/rdap+json, application/json' },
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (res.ok) {
          const ct = res.headers.get('content-type') || '';
          if (!ct.includes('json') && !ct.includes('rdap')) continue;
          const payload = await res.json();
          if (payload && (payload.ldhName || payload.objectClassName || payload.events || payload.nameservers)) {
            rdapData = payload;
            rawText = canonicalizeJsonStringify(payload);
            break;
          }
        }
      } catch {}
    }
  };

  // Run RDAP, DoH DNS, and CT Subdomain discovery concurrently
  const [, nsRes, aRes, aaaaRes, mxRes, dsRes, ctData] = await Promise.all([
    fetchRdap(),
    queryBrowserDoh(clean, 'NS'),
    queryBrowserDoh(clean, 'A'),
    queryBrowserDoh(clean, 'AAAA'),
    queryBrowserDoh(clean, 'MX'),
    queryBrowserDoh(root, 'DS'),
    fetchClientCtSubdomains(root),
  ]);

  if (rdapData) {
    const readScalar = (val: unknown): string => {
      if (typeof val === 'string') return val.trim();
      if (Array.isArray(val)) return val.map((x) => (typeof x === 'string' ? x.trim() : '')).filter(Boolean).join(' ');
      return '';
    };

    const parseEntities = (entities: any[]) => {
      if (!Array.isArray(entities)) return;
      for (const ent of entities) {
        const roles = Array.isArray(ent.roles) ? ent.roles.map((r: any) => String(r).toLowerCase()) : [];
        const vcardProps = Array.isArray(ent.vcardArray) && Array.isArray(ent.vcardArray[1]) ? ent.vcardArray[1] : null;
        if (roles.includes('registrar') || roles.includes('sponsor')) {
          if (vcardProps) {
            const fnItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'fn');
            const fnVal = fnItem ? readScalar(fnItem[3]) : '';
            if (fnVal) registrar = fnVal;
            const orgItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'org');
            const orgVal = orgItem ? readScalar(orgItem[3]) : '';
            if (registrar === 'Protected / Redacted' && orgVal) registrar = orgVal;
          }
          if (registrar === 'Protected / Redacted' && ent.handle) registrar = String(ent.handle);
          if (Array.isArray(ent.publicIds)) {
            const ianaPublicId = ent.publicIds.find(
              (p: any) => p && typeof p.type === 'string' && p.type.toLowerCase().includes('iana')
            );
            if (ianaPublicId && ianaPublicId.identifier !== undefined) ianaId = String(ianaPublicId.identifier);
          }
        }
        if (roles.includes('abuse')) {
          if (vcardProps) {
            const emailItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'email');
            const emailVal = emailItem ? readScalar(emailItem[3]).replace(/^mailto:/i, '') : '';
            if (emailVal) abuseContactEmail = emailVal;
            const telItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'tel');
            const telVal = telItem ? readScalar(telItem[3]).replace(/^tel:/i, '') : '';
            if (!abuseContactEmail && telVal) abuseContactEmail = telVal;
          }
        }
        if (roles.includes('registrant')) {
          if (vcardProps) {
            const orgItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'org');
            const orgVal = orgItem ? readScalar(orgItem[3]) : '';
            if (orgVal) registrantOrg = orgVal;
            const fnItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'fn');
            const fnVal = fnItem ? readScalar(fnItem[3]) : '';
            if (!registrantOrg && fnVal && !/redacted|privacy|not disclosed/i.test(fnVal)) {
              registrantOrg = fnVal;
            }
            const adrItem = vcardProps.find((i: any) => Array.isArray(i) && i[0] === 'adr');
            if (adrItem && Array.isArray(adrItem[3])) {
              if (adrItem[3][4]) registrantCity = readScalar(adrItem[3][4]) || String(adrItem[3][3] || '');
              if (adrItem[3][5]) registrantState = String(adrItem[3][5]);
              if (adrItem[3][6]) registrantCountry = String(adrItem[3][6]);
            }
            if (!registrantCountry && adrItem && adrItem[1] && typeof adrItem[1].cc === 'string') {
              registrantCountry = adrItem[1].cc;
            }
          }
        }
        if (ent.entities) parseEntities(ent.entities);
      }
    };
    if (rdapData.entities) parseEntities(rdapData.entities);

    if (!registrantOrg && Array.isArray(rdapData.auData_eligibility)) {
      const regEntry = rdapData.auData_eligibility.find(
        (item: any) => item && typeof item.name === 'string' && item.name.toLowerCase() === 'registrant name' && item.value
      );
      if (regEntry) registrantOrg = String(regEntry.value).trim();
    }

    if (registrar === 'Protected / Redacted' && rdapData.port43) {
      registrar = String(rdapData.port43);
    }

    if (rdapData.events && Array.isArray(rdapData.events)) {
      for (const ev of rdapData.events) {
        const action = String(ev?.eventAction || '').toLowerCase();
        if (action === 'registration' || action === 'created') createdDate = ev.eventDate;
        if (action === 'last changed' || action === 'last update') updatedDate = ev.eventDate;
        if (action === 'expiration' || action === 'expiry') expiresDate = ev.eventDate;
      }
    }

    if (Array.isArray(rdapData.status)) {
      rdapData.status.forEach((st: any) => {
        if (typeof st === 'string' && st.trim() && !status.includes(st.trim())) status.push(st.trim());
      });
    }

    if (Array.isArray(rdapData.nameservers)) {
      rdapData.nameservers.forEach((ns: any) => {
        const val = typeof ns === 'string' ? ns : ns?.ldhName || ns?.unicodeName || ns?.handle;
        const cleanNs = typeof val === 'string' ? val.trim().replace(/\.$/, '').toLowerCase() : '';
        if (cleanNs && !nameservers.includes(cleanNs)) nameservers.push(cleanNs);
      });
    }
  }

  (nsRes.Answer || []).forEach((ans: any) => {
    if (ans.type !== 2) return;
    const val = String(ans.data || '').replace(/\.$/, '').toLowerCase();
    if (val && !nameservers.includes(val)) nameservers.push(val);
  });

  (aRes.Answer || []).forEach((ans: any) => {
    if (ans.type !== 1) return;
    const val = String(ans.data || '').trim();
    if (val && !aRecords.includes(val)) aRecords.push(val);
  });

  (aaaaRes.Answer || []).forEach((ans: any) => {
    if (ans.type !== 28) return;
    const val = String(ans.data || '').trim();
    if (val && !aaaaRecords.includes(val)) aaaaRecords.push(val);
  });

  (mxRes.Answer || []).forEach((ans: any) => {
    if (ans.type !== 15) return;
    const parts = String(ans.data || '').trim().split(/\s+/);
    const val =
      parts.length >= 2 && /^\d+$/.test(parts[0])
        ? `${parts[1].replace(/\.$/, '')} (priority ${parts[0]})`
        : String(ans.data || '').replace(/\.$/, '');
    if (val && !mxRecords.includes(val)) mxRecords.push(val);
  });

  const dsAnswers = (dsRes.Answer || []).filter((ans: any) => ans.type === 43);
  const dnssec: 'signed' | 'unsigned' = dsAnswers.length > 0 ? 'signed' : 'unsigned';

  const asnInfo = aRecords.length > 0 ? await lookupClientIpAsn(aRecords[0]) : {};

  const ageData = formatDomainAge(createdDate);
  const expData = formatExpirationCountdown(expiresDate);
  const nameserverRoots = Array.from(new Set(nameservers.map((ns) => extractApexDomain(ns)).filter(Boolean))).sort();

  if (!rawText) {
    rawText = [
      `Domain Name: ${clean.toUpperCase()}`,
      `Root Domain: ${root}`,
      `Registrar: ${registrar}`,
      `Name Server: ${nameservers.join(', ') || 'Not resolved'}`,
      `DNSSEC: ${dnssec}`,
      `Source: RFC 8484 DoH / RFC 7480 RDAP Browser Probe`,
    ].join('\n');
  }

  return {
    queryInput: domain,
    domainName: clean,
    rootDomain: root,
    tld,
    fetchedAt: Date.now(),
    source: rdapData ? 'rdap' : 'doh',
    registrar,
    ianaId,
    whoisServer: rdapData?.port43 || undefined,
    createdDate,
    updatedDate,
    expiresDate,
    domainAgeYears: ageData?.years,
    domainAgeFormatted: ageData?.formatted,
    daysUntilExpiration: expData?.days,
    expirationStatus: expData?.status || 'unknown',
    status: status.length > 0 ? status : ['ok'],
    dnssec,
    nameservers: nameservers.sort(),
    nameserverRoots,
    dnsProvider: inferDnsProvider(nameservers),
    aRecords,
    aaaaRecords,
    mxRecords,
    mailProvider: inferClientMailProvider(mxRecords),
    asn: asnInfo.asn,
    asnName: asnInfo.asnName,
    bgpPrefix: asnInfo.bgpPrefix,
    subnet24: asnInfo.subnet24,
    crtSubdomainsCount: ctData.crtSubdomainsCount,
    crtSubdomainsSample: ctData.crtSubdomainsSample,
    crtWildcardFound: ctData.crtWildcardFound,
    registrantOrg,
    registrantCountry,
    registrantState,
    registrantCity,
    abuseContactEmail,
    rawText,
  };
}

export async function fetchDomainWhois(domain: string): Promise<WhoisDomainRecord> {
  const clean = sanitizeDomainInput(domain);
  if (!isValidDomainFormat(clean)) {
    throw new Error(`Invalid domain syntax: "${domain}". Please enter a valid fully qualified domain name.`);
  }

  if (shouldUseBackendApi()) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 12000);
      const res = await fetch(`/api/whois?domain=${encodeURIComponent(clean)}`, {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });
      clearTimeout(timeout);

      const ct = res.headers.get('content-type') || '';
      if (res.ok && ct.includes('application/json')) {
        const data = await res.json();
        if (data && data.domainName) {
          backendApiAvailable = true;
          return enrichDomainWithBrowserDns(data as WhoisDomainRecord);
        }
      } else if (res.status === 404 || res.status === 405 || !ct.includes('application/json')) {
        backendApiAvailable = false;
      }
    } catch {
      // fallback to client-side probe
    }
  }

  const clientRecord = await fetchClientSideWhois(clean);
  return enrichDomainWithBrowserDns(clientRecord);
}

export async function fetchAndCompareWhois(domainA: string, domainB: string): Promise<WhoisDiffResult> {
  const cleanA = sanitizeDomainInput(domainA);
  const cleanB = sanitizeDomainInput(domainB);

  if (!isValidDomainFormat(cleanA)) {
    throw new Error(`Domain A "${domainA}" is not a valid domain name.`);
  }
  if (!isValidDomainFormat(cleanB)) {
    throw new Error(`Domain B "${domainB}" is not a valid domain name.`);
  }

  // Try server-side consolidated diff endpoint when backend is available, then enrich with pure browser-JS DoH lookups
  if (shouldUseBackendApi()) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 18000);
      const res = await fetch(`/api/whois-diff?domainA=${encodeURIComponent(cleanA)}&domainB=${encodeURIComponent(cleanB)}`, {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });
      clearTimeout(timeout);

      const ct = res.headers.get('content-type') || '';
      if (res.ok && ct.includes('application/json')) {
        const data = await res.json();
        if (data && data.domainA && data.domainB) {
          backendApiAvailable = true;
          const [enrichedA, enrichedB] = await Promise.all([
            enrichDomainWithBrowserDns(data.domainA as WhoisDomainRecord),
            enrichDomainWithBrowserDns(data.domainB as WhoisDomainRecord),
          ]);
          return computeWhoisDiff(enrichedA, enrichedB);
        }
      } else if (res.status === 404 || res.status === 405 || !ct.includes('application/json')) {
        backendApiAvailable = false;
      }
    } catch {}
  }

  // Concurrently fetch and enrich both records client-side
  const [recordA, recordB] = await Promise.all([
    fetchDomainWhois(cleanA),
    fetchDomainWhois(cleanB),
  ]);

  return computeWhoisDiff(recordA, recordB);
}
