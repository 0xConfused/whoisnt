// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  WhoisDomainRecord,
  FieldDiffItem,
  WhoisDiffResult,
  WhoisDiffSummary,
  SharedLinkageInsight,
  TextDiffLine,
  DiffStatus,
  CtCertificateEntry,
} from '../types';
import { extractApexDomain, sanitizeDomainInput, isValidDomainFormat, prioritizeSubdomainsForRecon } from '../utils/urlUtils';
import { enrichDomainWithBrowserDns, queryBrowserDoh } from './browserDnsService';
import { canonicalizeJsonStringify, formatCanonicalJsonText } from '../utils/jsonSort';
import { parseFlexibleDateMs } from '../utils/dateUtils';
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
} from '../utils/htmlRecon';

export { sanitizeDomainInput, isValidDomainFormat };

function inferDnsProvider(nameservers: string[]): string {
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

function parseDateToTimestamp(dateStr?: string): number | null {
  return parseFlexibleDateMs(dateStr);
}

function formatDomainAge(createdDateStr?: string): { years: number; formatted: string } | null {
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

function formatExpirationCountdown(expiresDateStr?: string): { days: number; status: 'active' | 'expiring-soon' | 'expired' } | null {
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

function compareValues(
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

function computeWhoisDiff(domainA: WhoisDomainRecord, domainB: WhoisDomainRecord): WhoisDiffResult {
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
      deltaSummary: sameSoaRname
        ? GENERIC_SOA_RNAMES.has(normalizeString(domainA.soaRname))
          ? 'Shared managed DNS hostmaster'
          : `CUSTOM HOSTMASTER MATCH: ${domainA.soaRname}`
        : undefined,
    });
  }

  // Analytics & Tracking IDs (GA4, UA, GTM, AdSense, Meta Pixel, Clarity, etc.)
  const analyticsA = domainA.analyticsIds || [];
  const analyticsB = domainB.analyticsIds || [];
  const setAnalyticsB = new Set(analyticsB.map((a) => a.toLowerCase()));
  const sharedAnalyticsIds = analyticsA.filter((a) => setAnalyticsB.has(a.toLowerCase()));

  if (analyticsA.length > 0 || analyticsB.length > 0) {
    fieldDiffs.push({
      id: 'analytics_ids',
      category: 'attribution',
      label: 'Analytics & Ad Tracking IDs',
      rfcOrSpec: 'HTML / First-Party JS Static Scan',
      valueA: analyticsA.length > 0 ? analyticsA : ['No tracking IDs extracted'],
      valueB: analyticsB.length > 0 ? analyticsB : ['No tracking IDs extracted'],
      status: compareValues(analyticsA, analyticsB),
      deltaSummary:
        sharedAnalyticsIds.length > 0
          ? `ATTRIBUTION MATCH: Shared tracking ID(s) (${sharedAnalyticsIds.join(', ')})`
          : 'Distinct analytics properties',
    });
  }

  // HTML Meta Verification Tokens
  const htmlTokA = (domainA.htmlVerificationTokens || []).map((t) => `${t.provider}: ${t.token}`);
  const htmlTokB = (domainB.htmlVerificationTokens || []).map((t) => `${t.provider}: ${t.token}`);
  const setHtmlTokB = new Set((domainB.htmlVerificationTokens || []).map((t) => t.token));
  const sharedHtmlTokens = (domainA.htmlVerificationTokens || []).filter((t) => setHtmlTokB.has(t.token));

  if (htmlTokA.length > 0 || htmlTokB.length > 0) {
    fieldDiffs.push({
      id: 'html_verification_tokens',
      category: 'attribution',
      label: 'HTML Meta Verification Tokens',
      rfcOrSpec: 'HTML <meta> Ownership Tags',
      valueA: htmlTokA.length > 0 ? htmlTokA : ['None detected in <head>'],
      valueB: htmlTokB.length > 0 ? htmlTokB : ['None detected in <head>'],
      status: compareValues(htmlTokA, htmlTokB),
      deltaSummary:
        sharedHtmlTokens.length > 0
          ? `ATTRIBUTION MATCH: ${sharedHtmlTokens.length} identical HTML verification meta tag(s)`
          : 'Separate webmaster verification meta tags',
    });
  }

  // Footer Copyright Notices & Extracted Holder Entities
  const copyrightNoticesA = domainA.footerCopyrights || [];
  const copyrightNoticesB = domainB.footerCopyrights || [];
  const copyrightEntitiesA = domainA.copyrightEntities || [];
  const copyrightEntitiesB = domainB.copyrightEntities || [];
  const normCopyrightB = new Set(copyrightEntitiesB.map((e) => normalizeString(e)).filter(Boolean));
  const sharedCopyrightEntities = Array.from(
    new Set(copyrightEntitiesA.filter((e) => normCopyrightB.has(normalizeString(e))))
  ).sort();

  if (copyrightNoticesA.length > 0 || copyrightNoticesB.length > 0) {
    const compareTargetA = copyrightEntitiesA.length > 0 ? copyrightEntitiesA : copyrightNoticesA;
    const compareTargetB = copyrightEntitiesB.length > 0 ? copyrightEntitiesB : copyrightNoticesB;
    fieldDiffs.push({
      id: 'footer_copyright',
      category: 'attribution',
      label: 'Footer Copyright Notice & Holder',
      rfcOrSpec: 'HTML <footer> Copyright Extraction',
      valueA: copyrightNoticesA.length > 0 ? copyrightNoticesA : ['No footer copyright notice detected'],
      valueB: copyrightNoticesB.length > 0 ? copyrightNoticesB : ['No footer copyright notice detected'],
      status: compareValues(compareTargetA, compareTargetB),
      deltaSummary:
        sharedCopyrightEntities.length > 0
          ? `ATTRIBUTION MATCH: Shared copyright holder (${sharedCopyrightEntities.join(', ')})`
          : copyrightNoticesA.length > 0 && copyrightNoticesB.length > 0
          ? `Distinct copyright holders (${copyrightEntitiesA[0] || 'A'} vs ${copyrightEntitiesB[0] || 'B'})`
          : 'Footer copyright notice present on single target only',
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
  });

  // Live TLS Issuer CA
  fieldDiffs.push({
    id: 'tls_issuer_ca',
    category: 'certificates',
    label: 'SSL/TLS Certificate Authority',
    rfcOrSpec: 'RFC 5280 CA / CT Log Hierarchy',
    valueA: domainA.tlsIssuerOrg ? `${domainA.tlsIssuerOrg}${domainA.tlsIssuerCn ? ` [${domainA.tlsIssuerCn}]` : ''}` : 'Probe Unresolved',
    valueB: domainB.tlsIssuerOrg ? `${domainB.tlsIssuerOrg}${domainB.tlsIssuerCn ? ` [${domainB.tlsIssuerCn}]` : ''}` : 'Probe Unresolved',
    status: compareValues(domainA.tlsIssuerOrg, domainB.tlsIssuerOrg),
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
    });
  }

  // TLS Validity Window
  if (domainA.tlsValidityNotAfter || domainB.tlsValidityNotAfter) {
    const valA = domainA.tlsValidityNotAfter
      ? `${domainA.tlsValidityNotBefore || '?'} -> ${domainA.tlsValidityNotAfter}`
      : 'Not inspected';
    const valB = domainB.tlsValidityNotAfter
      ? `${domainB.tlsValidityNotBefore || '?'} -> ${domainB.tlsValidityNotAfter}`
      : 'Not inspected';
    fieldDiffs.push({
      id: 'tls_validity',
      category: 'certificates',
      label: 'X.509 Certificate Validity Window',
      rfcOrSpec: 'RFC 5280 NotBefore / NotAfter',
      valueA: valA,
      valueB: valB,
      status: compareValues(valA, valB),
    });
  }

  // Certificate Transparency (crt.name / Certspotter) Subdomains
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
    rfcOrSpec: 'RFC 6962 CT Logs',
    valueA: `${domainA.crtSubdomainsCount?.toLocaleString() || 0} subdomains discovered${domainA.crtWildcardFound ? ' [Wildcard *. cert]' : ''}`,
    valueB: `${domainB.crtSubdomainsCount?.toLocaleString() || 0} subdomains discovered${domainB.crtWildcardFound ? ' [Wildcard *. cert]' : ''}`,
    status:
      domainA.crtSubdomainsCount === domainB.crtSubdomainsCount
        ? 'MATCH'
        : 'DIFF',
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
      deltaSummary:
        sharedPtrHostnames.length > 0
          ? `IDENTICAL PTR HOSTNAME: ${sharedPtrHostnames.join(', ')}`
          : undefined,
    });
  }

  // Passive DNS Historical Resolutions & IPs
  const pdnsDispA = domainA.passiveDnsDisplay || [];
  const pdnsDispB = domainB.passiveDnsDisplay || [];
  const pdnsIpsA = domainA.passiveDnsIps || [];
  const pdnsIpsB = domainB.passiveDnsIps || [];
  const setPdnsIpB = new Set(pdnsIpsB);
  const sharedPassiveDnsIps = pdnsIpsA.filter((ip) => setPdnsIpB.has(ip));

  if (pdnsDispA.length > 0 || pdnsDispB.length > 0) {
    fieldDiffs.push({
      id: 'passive_dns_records',
      category: 'network',
      label: 'Passive DNS Historical Resolutions',
      rfcOrSpec: 'PDNS / Historical IP Footprint',
      valueA: pdnsDispA.length > 0 ? pdnsDispA : ['No historical PDNS records observed'],
      valueB: pdnsDispB.length > 0 ? pdnsDispB : ['No historical PDNS records observed'],
      status: compareValues(pdnsIpsA.length > 0 ? pdnsIpsA : pdnsDispA, pdnsIpsB.length > 0 ? pdnsIpsB : pdnsDispB),
      deltaSummary:
        sharedPassiveDnsIps.length > 0
          ? `HISTORICAL IP OVERLAP: ${sharedPassiveDnsIps.slice(0, 4).join(', ')}`
          : 'Distinct historical DNS resolution footprints',
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
    });
  }

  // ==========================================
  // 3B. WEB STACK, HEADERS, DOM & RESOURCES (STATIC / ZERO-EXECUTION)
  // ==========================================

  const formatWebStatus = (d: WhoisDomainRecord) => {
    if (d.webReconMode === 'cors-blocked') return 'Blocked by Target CORS Policy (Use backend server for direct inspection)';
    if (d.webReconMode === 'unreachable') return 'Unreachable over HTTP/HTTPS';
    if (!d.httpStatusCode && !d.webFinalUrl) return 'Not available';
    const scriptsNote = d.inspectedScriptsCount ? ` · ${d.inspectedScriptsCount} first-party JS scanned (static text only)` : '';
    const subNote = d.webReconProbedHostsCount
      ? ` · ${d.webReconReachableHosts?.length || 0}/${d.webReconProbedHostsCount} hosts reachable`
      : '';
    return `HTTP ${d.httpStatusCode || '?'} · ${d.webFinalUrl || `https://${d.domainName}`} [${d.webReconMode || 'direct'}]${subNote}${scriptsNote}`;
  };

  if (domainA.webReconMode || domainB.webReconMode) {
    fieldDiffs.push({
      id: 'web_recon_status',
      category: 'web',
      label: 'HTTP Probe & Resource Access Mode',
      rfcOrSpec: 'RFC 9110 / Multi-Subdomain Static Fetch',
      valueA: formatWebStatus(domainA),
      valueB: formatWebStatus(domainB),
      status: compareValues(domainA.webFinalUrl || domainA.webReconMode, domainB.webFinalUrl || domainB.webReconMode),
    });
  }

  const hostsA = domainA.webReconReachableHosts || [];
  const hostsB = domainB.webReconReachableHosts || [];
  if (hostsA.length > 0 || hostsB.length > 0) {
    fieldDiffs.push({
      id: 'web_probed_hosts',
      category: 'web',
      label: 'Reachable Subdomains Inspected',
      rfcOrSpec: 'Multi-Subdomain HTTP Surface',
      valueA: hostsA.length > 0 ? hostsA : ['No reachable subdomains observed'],
      valueB: hostsB.length > 0 ? hostsB : ['No reachable subdomains observed'],
      status: compareValues(hostsA, hostsB),
    });
  }

  const hdrsA = domainA.httpHeaderSummary || [];
  const hdrsB = domainB.httpHeaderSummary || [];
  if (hdrsA.length > 0 || hdrsB.length > 0) {
    fieldDiffs.push({
      id: 'http_headers',
      category: 'web',
      label: 'Sanitized HTTP Response Headers',
      rfcOrSpec: 'RFC 9110 / Security Headers',
      valueA: hdrsA.length > 0 ? hdrsA : ['Headers not exposed / CORS restricted'],
      valueB: hdrsB.length > 0 ? hdrsB : ['Headers not exposed / CORS restricted'],
      status: compareValues(hdrsA, hdrsB),
    });
  }

  const cspExtA = domainA.cspExternalDomains || [];
  const cspExtB = domainB.cspExternalDomains || [];
  if (cspExtA.length > 0 || cspExtB.length > 0) {
    fieldDiffs.push({
      id: 'csp_external_domains',
      category: 'web',
      label: 'CSP External Origin Whitelist',
      rfcOrSpec: 'W3C Content-Security-Policy',
      valueA: cspExtA.length > 0 ? cspExtA : ['None declared in CSP'],
      valueB: cspExtB.length > 0 ? cspExtB : ['None declared in CSP'],
      status: compareValues(cspExtA, cspExtB),
    });
  }

  const formatHtmlMeta = (d: WhoisDomainRecord): string[] => {
    const items: string[] = [];
    if (d.htmlTitle) items.push(`Title: ${d.htmlTitle}`);
    if (d.openGraphSiteName) items.push(`OG Site Name: ${d.openGraphSiteName}`);
    if (d.htmlGenerator) items.push(`Generator: ${d.htmlGenerator}`);
    if (d.htmlAuthor) items.push(`Author: ${d.htmlAuthor}`);
    if (d.twitterSite) items.push(`Twitter Site: ${d.twitterSite}`);
    if (d.canonicalUrl) items.push(`Canonical: ${d.canonicalUrl}`);
    if (d.htmlRobots) items.push(`Robots: ${d.htmlRobots}`);
    if (d.htmlDescription) items.push(`Description: ${d.htmlDescription}`);
    return items;
  };
  const metaA = formatHtmlMeta(domainA);
  const metaB = formatHtmlMeta(domainB);
  if (metaA.length > 0 || metaB.length > 0) {
    fieldDiffs.push({
      id: 'html_metadata',
      category: 'web',
      label: 'HTML Metadata & Canonical Identity',
      rfcOrSpec: 'HTML5 <meta> / OpenGraph',
      valueA: metaA.length > 0 ? metaA : ['No HTML metadata extracted'],
      valueB: metaB.length > 0 ? metaB : ['No HTML metadata extracted'],
      status: compareValues(metaA, metaB),
    });
  }

  const domItemsA = [...(domainA.domMarkers || []), ...(domainA.domStats ? [`Stats: ${domainA.domStats}`] : [])];
  const domItemsB = [...(domainB.domMarkers || []), ...(domainB.domStats ? [`Stats: ${domainB.domStats}`] : [])];
  if (domItemsA.length > 0 || domItemsB.length > 0) {
    fieldDiffs.push({
      id: 'dom_inspection',
      category: 'web',
      label: 'DOM Structure & Framework Mounts',
      rfcOrSpec: 'Inert DOMParser Inspection',
      valueA: domItemsA.length > 0 ? domItemsA : ['No DOM structure parsed'],
      valueB: domItemsB.length > 0 ? domItemsB : ['No DOM structure parsed'],
      status: compareValues(domainA.domMarkers || [], domainB.domMarkers || []),
    });
  }

  const techA = domainA.technologies || [];
  const techB = domainB.technologies || [];
  const setTechB = new Set(techB.map((t) => t.toLowerCase()));
  const sharedTechnologies = techA.filter((t) => setTechB.has(t.toLowerCase()));
  if (techA.length > 0 || techB.length > 0) {
    fieldDiffs.push({
      id: 'technologies',
      category: 'web',
      label: 'Web Technology Fingerprints',
      rfcOrSpec: 'Headers / DOM / Asset Signatures',
      valueA: techA.length > 0 ? techA : ['No stack signatures matched'],
      valueB: techB.length > 0 ? techB : ['No stack signatures matched'],
      status: compareValues(techA, techB),
      deltaSummary:
        sharedTechnologies.length > 0
          ? `Shared stack components: ${sharedTechnologies.join(', ')}`
          : 'Divergent application stack',
    });
  }

  const scriptsA = domainA.scriptUrls || [];
  const scriptsB = domainB.scriptUrls || [];
  if (scriptsA.length > 0 || scriptsB.length > 0) {
    fieldDiffs.push({
      id: 'script_urls',
      category: 'web',
      label: 'Collected Script URLs (<script src>)',
      rfcOrSpec: 'Static HTML Tag Enumeration',
      valueA: scriptsA.length > 0 ? scriptsA : ['No external/linked scripts'],
      valueB: scriptsB.length > 0 ? scriptsB : ['No external/linked scripts'],
      status: compareValues(scriptsA, scriptsB),
    });
  }

  const resA = domainA.resourceSummary || [];
  const resB = domainB.resourceSummary || [];
  if (resA.length > 0 || resB.length > 0) {
    fieldDiffs.push({
      id: 'resource_enumeration',
      category: 'web',
      label: 'Enumerated Resources (CSS / Icons / Media)',
      rfcOrSpec: 'Static HTML & CSS Asset URLs',
      valueA: resA.length > 0 ? resA : ['No static assets enumerated'],
      valueB: resB.length > 0 ? resB : ['No static assets enumerated'],
      status: compareValues(resA, resB),
    });
  }

  const extDomA = domainA.externalDomains || [];
  const extDomB = domainB.externalDomains || [];
  const setExtDomB = new Set(extDomB.map((d) => d.toLowerCase()));
  const sharedExternalDomains = extDomA.filter((d) => setExtDomB.has(d.toLowerCase()));
  if (extDomA.length > 0 || extDomB.length > 0) {
    fieldDiffs.push({
      id: 'external_domains',
      category: 'web',
      label: 'Discovered External Third-Party Domains',
      rfcOrSpec: 'Outbound Links, Assets & CSP',
      valueA: extDomA.length > 0 ? extDomA : ['No external domains discovered'],
      valueB: extDomB.length > 0 ? extDomB : ['No external domains discovered'],
      status: compareValues(extDomA, extDomB),
      deltaSummary:
        sharedExternalDomains.length > 0
          ? `SHARED EXTERNAL ORIGINS: ${sharedExternalDomains.slice(0, 5).join(', ')}`
          : 'Distinct external domain dependencies',
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
  });

  // SOA Primary Master (MNAME)
  if (domainA.soaMname || domainB.soaMname) {
    fieldDiffs.push({
      id: 'soa_mname',
      category: 'infrastructure',
      label: 'SOA Primary Master (MNAME)',
      rfcOrSpec: 'RFC 1035 SOA MNAME',
      valueA: domainA.soaMname ? `${domainA.soaMname}${domainA.soaSerial ? ` (serial ${domainA.soaSerial})` : ''}` : 'Not resolved',
      valueB: domainB.soaMname ? `${domainB.soaMname}${domainB.soaSerial ? ` (serial ${domainB.soaSerial})` : ''}` : 'Not resolved',
      status: compareValues(domainA.soaMname, domainB.soaMname),
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
    isLowImpact: !isCreationClustered && !isSignificantAgeDiscrepancy,
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
      isLowImpact: !isCreationClustered && !isUpdateClustered,
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
    isLowImpact: !isSignificantExpDiscrepancy,
    deltaSummary:
      expDaysDelta !== undefined
        ? isSignificantExpDiscrepancy
          ? `SIGNIFICANT EXPIRATION GAP: ${expDaysDelta.toLocaleString()} days`
          : `Synchronized expiration window (${expDaysDelta} days gap)`
        : undefined,
  });

  // Last Registry Update Timestamp (Hidden unless clustered)
  fieldDiffs.push({
    id: 'updated_date',
    category: 'lifecycle',
    label: 'Last Registry Touch / Update',
    rfcOrSpec: 'Automated Registry Sync',
    valueA: formatUtcPrecision(domainA.updatedDate),
    valueB: formatUtcPrecision(domainB.updatedDate),
    status: compareValues(domainA.updatedDate, domainB.updatedDate),
    isLowImpact: !isUpdateClustered,
    deltaSummary: isUpdateClustered
      ? `Registry updates within ${formatExactDuration(updatedDeltaSeconds!)}`
      : 'Routine registry sync timestamp (low analytical value)',
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

  if (sharedAnalyticsIds.length > 0) {
    linkages.push({
      type: 'attribution',
      title: 'Shared Analytics / Advertising Tracking ID',
      description: `Both targets embed identical analytics or publisher identifier(s): ${sharedAnalyticsIds.join(', ')}. Strong evidence of shared web property ownership.`,
      strength: 'definitive',
    });
  }

  if (sharedHtmlTokens.length > 0) {
    linkages.push({
      type: 'attribution',
      title: 'Shared HTML Meta Verification Token',
      description: `HTML <head> contains ${sharedHtmlTokens.length} identical verification tag(s) (${sharedHtmlTokens.map((t) => t.provider).join(', ')}).`,
      strength: 'definitive',
    });
  }

  if (sharedCopyrightEntities.length > 0) {
    linkages.push({
      type: 'attribution',
      title: 'Matching Footer Copyright Entity',
      description: `Both domains declare the identical legal copyright holder in their page footer: "${sharedCopyrightEntities.join('", "')}".`,
      strength: 'definitive',
    });
  }

  if (sharedPassiveDnsIps.length > 0) {
    linkages.push({
      type: 'network',
      title: 'Historical Passive DNS IP Overlap',
      description: `Passive DNS history shows both domains historically resolved to identical IP address(es): ${sharedPassiveDnsIps.slice(0, 4).join(', ')}.`,
      strength: 'strong',
    });
  }

  if (sharedExternalDomains.length > 0) {
    linkages.push({
      type: 'infrastructure',
      title: 'Shared External Resource Origins',
      description: `Both domains reference ${sharedExternalDomains.length} shared external third-party host(s) (${sharedExternalDomains.slice(0, 4).join(', ')}).`,
      strength: 'moderate',
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

  const summary: WhoisDiffSummary = {
    totalFieldsCompared: fieldDiffs.length,
    divergentCount,
    matchingCount,
    ageDeltaFormatted:
      ageDeltaYears !== undefined
        ? `${ageDeltaYears.toFixed(1)}y (${domainA.domainAgeYears! > domainB.domainAgeYears! ? domainA.domainName : domainB.domainName} older)`
        : undefined,
    expirationDeltaFormatted:
      expDaysDelta !== undefined
        ? `${expDaysDelta.toLocaleString()} days gap`
        : undefined,
    sharedNameserversCount: sharedNs.length,
    totalNameserversCount: unionNs.size,
    sameRegistrar: normalizeString(domainA.registrar) === normalizeString(domainB.registrar) && Boolean(domainA.registrar),
    sameDnsProvider: normalizeString(dnsProvA) === normalizeString(dnsProvB),
    sameMailProvider: mailProvA !== 'No MX Records Listed' && mailProvA !== 'No MX Records' && mailProvA === mailProvB,
    sameAsn,
    sameSubnet24: sameSubnet,
    sameTlsSubjectOrg: Boolean(domainA.tlsSubjectOrg && domainB.tlsSubjectOrg && normalizeString(domainA.tlsSubjectOrg) === normalizeString(domainB.tlsSubjectOrg)),
    sharedVerificationTokensCount: sharedTokens.length,
    sharedAnalyticsIds,
    sharedCopyrightEntities,
    sharedExternalDomains,
    sharedPassiveDnsIps,
    sameSoaRname,
    sharedPtrHostnames,
    sharedSpfIps,
    sameDmarcRua: dmarcRuaMatch,
    sameDmarcRuf: dmarcRufMatch,
    sharedDkimTargets,
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
    isSingleDomain: false,
    domainA: normalizedDomainA,
    domainB: normalizedDomainB,
    fieldDiffs,
    summary,
    rawTextDiff,
    computedAt: Date.now(),
  };
}

function computeSingleDomainResult(domain: WhoisDomainRecord): WhoisDiffResult {
  const fieldDiffs: FieldDiffItem[] = [];

  // 1. ATTRIBUTION PIVOTS
  fieldDiffs.push({
    id: 'registrant_org',
    category: 'attribution',
    label: 'Registrant Organization',
    rfcOrSpec: 'RDAP / WHOIS',
    valueA: domain.registrantOrg || 'Redacted for Privacy / Proxy',
    valueB: undefined,
    status: 'ONLY_A',
  });

  const tokens = (domain.verificationTokens || []).map((t) => `${t.provider}: ${t.token}`);
  fieldDiffs.push({
    id: 'verification_tokens',
    category: 'attribution',
    label: 'Domain Verification Tokens (TXT)',
    rfcOrSpec: 'RFC 1464 / Cloud IDP',
    valueA: tokens.length > 0 ? tokens : ['No third-party verification tokens detected'],
    valueB: undefined,
    status: 'ONLY_A',
  });

  const spfIncludes = domain.spfIncludes || [];
  fieldDiffs.push({
    id: 'spf_relays',
    category: 'attribution',
    label: 'Authorized Mail Relays (SPF)',
    rfcOrSpec: 'RFC 7208 SPF',
    valueA: spfIncludes.length > 0 ? spfIncludes : [domain.spfRecord || 'No SPF record'],
    valueB: undefined,
    status: 'ONLY_A',
  });

  const spfIps = domain.spfIpMechanisms || [];
  if (spfIps.length > 0) {
    fieldDiffs.push({
      id: 'spf_ip_leaks',
      category: 'attribution',
      label: 'SPF Origin IPs & Direct Mechanisms',
      rfcOrSpec: 'RFC 7208 ip4/ip6/redirect',
      valueA: spfIps,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.dmarcRua || domain.dmarcRuf || domain.dmarcPolicy) {
    const parts: string[] = [];
    if (domain.dmarcPolicy) parts.push(`p=${domain.dmarcPolicy}`);
    if (domain.dmarcRua) parts.push(`rua=${domain.dmarcRua}`);
    if (domain.dmarcRuf) parts.push(`ruf=${domain.dmarcRuf}`);
    fieldDiffs.push({
      id: 'dmarc_policy',
      category: 'attribution',
      label: 'DMARC Policy & Aggregate / Forensic URIs',
      rfcOrSpec: 'RFC 7489 DMARC (rua / ruf)',
      valueA: parts.join(' | ') || 'No DMARC Record',
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  const dkim = domain.dkimSelectors || [];
  if (dkim.length > 0) {
    fieldDiffs.push({
      id: 'dkim_selectors',
      category: 'attribution',
      label: 'DKIM Selectors & CNAME Tenants',
      rfcOrSpec: 'RFC 6376 _domainkey',
      valueA: dkim,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.soaRname) {
    fieldDiffs.push({
      id: 'soa_rname',
      category: 'attribution',
      label: 'SOA Hostmaster Contact (RNAME)',
      rfcOrSpec: 'RFC 1035 SOA RNAME',
      valueA: domain.soaRname,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  const analytics = domain.analyticsIds || [];
  if (analytics.length > 0) {
    fieldDiffs.push({
      id: 'analytics_ids',
      category: 'attribution',
      label: 'Analytics & Ad Tracking IDs',
      rfcOrSpec: 'HTML / First-Party JS Static Scan',
      valueA: analytics,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  const htmlTokens = (domain.htmlVerificationTokens || []).map((t) => `${t.provider}: ${t.token}`);
  if (htmlTokens.length > 0) {
    fieldDiffs.push({
      id: 'html_verification_tokens',
      category: 'attribution',
      label: 'HTML Meta Verification Tokens',
      rfcOrSpec: 'HTML <meta> Ownership Tags',
      valueA: htmlTokens,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  const copyrightNotices = domain.footerCopyrights || [];
  if (copyrightNotices.length > 0) {
    fieldDiffs.push({
      id: 'footer_copyright',
      category: 'attribution',
      label: 'Footer Copyright Notice & Holder',
      rfcOrSpec: 'HTML <footer> Copyright Extraction',
      valueA: copyrightNotices,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  fieldDiffs.push({
    id: 'registrant_country',
    category: 'attribution',
    label: 'Registrant Country / State',
    rfcOrSpec: 'ISO 3166-1 / ISO 3166-2',
    valueA: domain.registrantCountry
      ? `${domain.registrantCountry.toUpperCase()}${domain.registrantState ? ` (${domain.registrantState})` : ''}`
      : 'Redacted / Not Disclosed',
    valueB: undefined,
    status: 'ONLY_A',
  });

  // 2. CERTIFICATES & TLS
  fieldDiffs.push({
    id: 'tls_subject_org',
    category: 'certificates',
    label: 'SSL/TLS Subject Organization',
    rfcOrSpec: 'RFC 5280 X.509',
    valueA: domain.tlsSubjectOrg
      ? `${domain.tlsSubjectOrg} (${domain.tlsSubjectCn || domain.domainName})`
      : domain.tlsSubjectCn || 'Domain Validation (DV Only)',
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'tls_issuer_ca',
    category: 'certificates',
    label: 'SSL/TLS Certificate Authority',
    rfcOrSpec: 'RFC 5280 CA / CT Log Hierarchy',
    valueA: domain.tlsIssuerOrg
      ? `${domain.tlsIssuerOrg}${domain.tlsIssuerCn ? ` [${domain.tlsIssuerCn}]` : ''}`
      : 'Probe Unresolved',
    valueB: undefined,
    status: 'ONLY_A',
  });

  if (domain.tlsProtocol) {
    fieldDiffs.push({
      id: 'tls_protocol',
      category: 'certificates',
      label: 'Negotiated TLS Protocol & Cipher',
      rfcOrSpec: 'RFC 8446 TLS 1.3',
      valueA: `${domain.tlsProtocol} (${domain.tlsCipher || 'Default Cipher'})`,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.tlsValidityNotAfter) {
    fieldDiffs.push({
      id: 'tls_validity',
      category: 'certificates',
      label: 'X.509 Certificate Validity Window',
      rfcOrSpec: 'RFC 5280 NotBefore / NotAfter',
      valueA: `${domain.tlsValidityNotBefore || '?'} -> ${domain.tlsValidityNotAfter}`,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  fieldDiffs.push({
    id: 'crt_subdomains_count',
    category: 'certificates',
    label: 'Certificate Transparency Subdomains',
    rfcOrSpec: 'RFC 6962 CT Logs',
    valueA: `${domain.crtSubdomainsCount?.toLocaleString() || 0} subdomains discovered${domain.crtWildcardFound ? ' [Wildcard *. cert]' : ''}`,
    valueB: undefined,
    status: 'ONLY_A',
  });

  // 3. NETWORK & BGP
  fieldDiffs.push({
    id: 'bgp_asn',
    category: 'network',
    label: 'Autonomous System (BGP ASN)',
    rfcOrSpec: 'RFC 1930 / Team Cymru BGP',
    valueA: domain.asn ? `${domain.asn}${domain.asnName ? ` (${domain.asnName})` : ''}` : 'Unrouted / Private',
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'subnet_24',
    category: 'network',
    label: 'IPv4 /24 Subnet Allocation',
    rfcOrSpec: 'CIDR Routing Prefix',
    valueA: domain.subnet24 || 'None resolved',
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'a_records',
    category: 'network',
    label: 'IPv4 Addresses (A Records)',
    rfcOrSpec: 'RFC 1035 A',
    valueA: domain.aRecords?.length ? domain.aRecords : ['None resolved'],
    valueB: undefined,
    status: 'ONLY_A',
  });

  const ptrs = domain.ptrRecords || [];
  if (ptrs.length > 0) {
    fieldDiffs.push({
      id: 'ptr_records',
      category: 'network',
      label: 'Reverse DNS (PTR Hostnames)',
      rfcOrSpec: 'RFC 1035 / RFC 3596 PTR',
      valueA: ptrs,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  const pdnsDisp = domain.passiveDnsDisplay || [];
  if (pdnsDisp.length > 0) {
    fieldDiffs.push({
      id: 'passive_dns_records',
      category: 'network',
      label: 'Passive DNS Historical Resolutions',
      rfcOrSpec: 'PDNS / Historical IP Footprint',
      valueA: pdnsDisp,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.httpWebServer) {
    fieldDiffs.push({
      id: 'web_server',
      category: 'network',
      label: 'Edge Web Server Technology',
      rfcOrSpec: 'RFC 9110 HTTP Server Header',
      valueA: `${domain.httpWebServer} (HTTP ${domain.httpStatusCode || 200})`,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  // 3B. WEB RECON & PASSIVE DNS
  const formatWebStatus = (d: WhoisDomainRecord) => {
    if (d.webReconMode === 'cors-blocked') return 'Blocked by Target CORS Policy (Use backend server for direct inspection)';
    if (d.webReconMode === 'unreachable') return 'Unreachable over HTTP/HTTPS';
    if (!d.httpStatusCode && !d.webFinalUrl) return 'Not available';
    const scriptsNote = d.inspectedScriptsCount ? ` · ${d.inspectedScriptsCount} first-party JS scanned (static text only)` : '';
    const subNote = d.webReconProbedHostsCount
      ? ` · ${d.webReconReachableHosts?.length || 0}/${d.webReconProbedHostsCount} hosts reachable`
      : '';
    return `HTTP ${d.httpStatusCode || '?'} · ${d.webFinalUrl || `https://${d.domainName}`} [${d.webReconMode || 'direct'}]${subNote}${scriptsNote}`;
  };

  if (domain.webReconMode) {
    fieldDiffs.push({
      id: 'web_recon_status',
      category: 'web',
      label: 'HTTP Probe & Resource Access Mode',
      rfcOrSpec: 'RFC 9110 / Multi-Subdomain Static Fetch',
      valueA: formatWebStatus(domain),
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.webReconReachableHosts && domain.webReconReachableHosts.length > 0) {
    fieldDiffs.push({
      id: 'web_probed_hosts',
      category: 'web',
      label: 'Reachable Subdomains Inspected',
      rfcOrSpec: 'Multi-Subdomain HTTP Surface',
      valueA: domain.webReconReachableHosts,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.httpHeaderSummary && domain.httpHeaderSummary.length > 0) {
    fieldDiffs.push({
      id: 'http_headers',
      category: 'web',
      label: 'Sanitized HTTP Response Headers',
      rfcOrSpec: 'RFC 9110 / Security Headers',
      valueA: domain.httpHeaderSummary,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.cspExternalDomains && domain.cspExternalDomains.length > 0) {
    fieldDiffs.push({
      id: 'csp_external_domains',
      category: 'web',
      label: 'CSP External Origin Whitelist',
      rfcOrSpec: 'W3C Content-Security-Policy',
      valueA: domain.cspExternalDomains,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  const metaItems: string[] = [];
  if (domain.htmlTitle) metaItems.push(`Title: ${domain.htmlTitle}`);
  if (domain.openGraphSiteName) metaItems.push(`OG Site Name: ${domain.openGraphSiteName}`);
  if (domain.htmlGenerator) metaItems.push(`Generator: ${domain.htmlGenerator}`);
  if (domain.htmlAuthor) metaItems.push(`Author: ${domain.htmlAuthor}`);
  if (domain.twitterSite) metaItems.push(`Twitter Site: ${domain.twitterSite}`);
  if (domain.canonicalUrl) metaItems.push(`Canonical: ${domain.canonicalUrl}`);
  if (domain.htmlRobots) metaItems.push(`Robots: ${domain.htmlRobots}`);
  if (domain.htmlDescription) metaItems.push(`Description: ${domain.htmlDescription}`);
  if (metaItems.length > 0) {
    fieldDiffs.push({
      id: 'html_metadata',
      category: 'web',
      label: 'HTML Metadata & Canonical Identity',
      rfcOrSpec: 'HTML5 <meta> / OpenGraph',
      valueA: metaItems,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  const domItems = [...(domain.domMarkers || []), ...(domain.domStats ? [`Stats: ${domain.domStats}`] : [])];
  if (domItems.length > 0) {
    fieldDiffs.push({
      id: 'dom_inspection',
      category: 'web',
      label: 'DOM Structure & Framework Mounts',
      rfcOrSpec: 'Inert DOMParser Inspection',
      valueA: domItems,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.technologies && domain.technologies.length > 0) {
    fieldDiffs.push({
      id: 'technologies',
      category: 'web',
      label: 'Web Technology Fingerprints',
      rfcOrSpec: 'Headers / DOM / Asset Signatures',
      valueA: domain.technologies,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.scriptUrls && domain.scriptUrls.length > 0) {
    fieldDiffs.push({
      id: 'script_urls',
      category: 'web',
      label: 'Collected Script URLs (<script src>)',
      rfcOrSpec: 'Static HTML Tag Enumeration',
      valueA: domain.scriptUrls,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.resourceSummary && domain.resourceSummary.length > 0) {
    fieldDiffs.push({
      id: 'resource_enumeration',
      category: 'web',
      label: 'Enumerated Resources (CSS / Icons / Media)',
      rfcOrSpec: 'Static HTML & CSS Asset URLs',
      valueA: domain.resourceSummary,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.externalDomains && domain.externalDomains.length > 0) {
    fieldDiffs.push({
      id: 'external_domains',
      category: 'web',
      label: 'Discovered External Third-Party Domains',
      rfcOrSpec: 'Outbound Links, Assets & CSP',
      valueA: domain.externalDomains,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  // 4. DNS & MAIL INFRASTRUCTURE
  const dnsProv = domain.dnsProvider || inferDnsProvider(domain.nameservers);
  fieldDiffs.push({
    id: 'dns_provider',
    category: 'infrastructure',
    label: 'Managed DNS Provider',
    rfcOrSpec: 'Inferred via NS Cluster',
    valueA: dnsProv,
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'nameservers',
    category: 'infrastructure',
    label: 'Authoritative Nameservers',
    rfcOrSpec: 'RFC 1035 NS',
    valueA: domain.nameservers.length > 0 ? domain.nameservers : ['None listed'],
    valueB: undefined,
    status: 'ONLY_A',
  });

  if (domain.soaMname) {
    fieldDiffs.push({
      id: 'soa_mname',
      category: 'infrastructure',
      label: 'SOA Primary Master (MNAME)',
      rfcOrSpec: 'RFC 1035 SOA MNAME',
      valueA: `${domain.soaMname}${domain.soaSerial ? ` (serial ${domain.soaSerial})` : ''}`,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  fieldDiffs.push({
    id: 'mail_provider',
    category: 'infrastructure',
    label: 'Enterprise Mail Solution',
    rfcOrSpec: 'RFC 5321 MX Exchange',
    valueA: domain.mailProvider || 'No MX Records',
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'dnssec',
    category: 'security',
    label: 'DNSSEC Cryptographic Signing',
    rfcOrSpec: 'RFC 4033 / 4034',
    valueA: domain.dnssec.toUpperCase(),
    valueB: undefined,
    status: 'ONLY_A',
  });

  const keys = [
    ...(domain.dsRecords || []).map((d) => `DS: ${d}`),
    ...(domain.dnskeyRecords || []).map((k) => `DNSKEY: ${k}`),
  ];
  if (keys.length > 0) {
    fieldDiffs.push({
      id: 'dnssec_keys',
      category: 'security',
      label: 'DNSSEC DS & DNSKEY Material',
      rfcOrSpec: 'RFC 4034 DS / DNSKEY',
      valueA: keys,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  if (domain.caaRecords && domain.caaRecords.length > 0) {
    fieldDiffs.push({
      id: 'caa_records',
      category: 'security',
      label: 'CAA Certificate Policies & IODEF',
      rfcOrSpec: 'RFC 8659 CAA',
      valueA: domain.caaRecords,
      valueB: undefined,
      status: 'ONLY_A',
    });
  }

  // 5. REGISTRAR & EPP SECURITY
  fieldDiffs.push({
    id: 'registrar_name',
    category: 'registrar',
    label: 'Sponsoring Registrar',
    rfcOrSpec: 'ICANN RAA',
    valueA: domain.registrar || 'Protected / Redacted',
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'epp_status',
    category: 'security',
    label: 'EPP Domain Status Locks',
    rfcOrSpec: 'RFC 5731 EPP',
    valueA: domain.status.length > 0 ? domain.status : ['ok (unlocked)'],
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'abuse_email',
    category: 'registrar',
    label: 'Registrar Abuse Contact',
    rfcOrSpec: 'RFC 2142',
    valueA: domain.abuseContactEmail || 'Protected / Registry Proxy',
    valueB: undefined,
    status: 'ONLY_A',
  });

  // 6. LIFECYCLE & DATES
  fieldDiffs.push({
    id: 'domain_age',
    category: 'lifecycle',
    label: 'Domain Age & Inception',
    rfcOrSpec: 'Registry Creation Date',
    valueA: domain.domainAgeFormatted || (domain.domainAgeYears ? `${domain.domainAgeYears} years` : 'Undetermined'),
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'created_date',
    category: 'lifecycle',
    label: 'Registration Timestamp (UTC)',
    rfcOrSpec: 'ISO 8601 / RDAP Events',
    valueA: formatUtcPrecision(domain.createdDate),
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'days_until_expiration',
    category: 'lifecycle',
    label: 'Registry Expiration Horizon',
    rfcOrSpec: 'Renewal Countdown',
    valueA:
      domain.daysUntilExpiration !== undefined
        ? `${domain.daysUntilExpiration.toLocaleString()} days (${domain.expirationStatus?.toUpperCase()})`
        : 'Undetermined',
    valueB: undefined,
    status: 'ONLY_A',
  });

  fieldDiffs.push({
    id: 'updated_date',
    category: 'lifecycle',
    label: 'Last Registry Touch / Update',
    rfcOrSpec: 'Automated Registry Sync',
    valueA: formatUtcPrecision(domain.updatedDate),
    valueB: undefined,
    status: 'ONLY_A',
  });

  const normalizedRaw = formatCanonicalJsonText(domain.rawText || '');
  const normalizedDomain =
    normalizedRaw === (domain.rawText || '') ? domain : { ...domain, rawText: normalizedRaw };

  const rawLines = normalizedRaw.split(/\r?\n/).map((l) => l.trimEnd());
  const rawTextDiff: TextDiffLine[] = [
    { type: 'header', text: `--- ${domain.domainName} (WHOIS / RDAP Record)` },
    ...rawLines.slice(0, 1999).map((line, idx) => ({
      type: 'same' as const,
      text: `  ${line}`,
      lineA: idx + 1,
    })),
  ];

  const summary: WhoisDiffSummary = {
    totalFieldsCompared: fieldDiffs.length,
    divergentCount: 0,
    matchingCount: 0,
    sharedNameserversCount: 0,
    totalNameserversCount: domain.nameservers.length,
    sameRegistrar: false,
    sameDnsProvider: false,
    sameMailProvider: false,
    sameAsn: false,
    sameSubnet24: false,
    sameTlsSubjectOrg: false,
    sharedVerificationTokensCount: 0,
    linkages: [],
    overallAttributionVerdict: 'DISTINCT_INDEPENDENT_ENTITIES',
  };

  return {
    isSingleDomain: true,
    domainA: normalizedDomain,
    domainB: undefined,
    fieldDiffs,
    summary,
    rawTextDiff,
    computedAt: Date.now(),
  };
}

function computeTextDiff(textA: string, textB: string, labelA = 'Domain A', labelB = 'Domain B'): TextDiffLine[] {
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
): Promise<{ asn?: string; asnName?: string; subnet24?: string }> {
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
        return { asn, asnName, subnet24 };
      }
    }
  } catch {}

  // 2. Fallback: RIPEstat network-info (CORS *)
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
      if (rawAsn) {
        return {
          asn: `AS${String(rawAsn).replace(/^AS/i, '')}`,
          subnet24,
        };
      }
    }
  } catch {}

  return { subnet24 };
}

function decodeDerLength(bytes: Uint8Array, offset: number): { length: number; bytesUsed: number } | null {
  if (offset >= bytes.length) return null;
  const first = bytes[offset];
  if (first < 0x80) return { length: first, bytesUsed: 1 };
  const numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4 || offset + numBytes >= bytes.length) return null;
  let length = 0;
  for (let i = 1; i <= numBytes; i++) {
    length = (length << 8) | bytes[offset + i];
  }
  return { length, bytesUsed: 1 + numBytes };
}

function readDerTlv(
  bytes: Uint8Array,
  offset: number
): { tag: number; valueStart: number; valueEnd: number; next: number } | null {
  if (offset >= bytes.length) return null;
  const tag = bytes[offset];
  const lenInfo = decodeDerLength(bytes, offset + 1);
  if (!lenInfo) return null;
  const valueStart = offset + 1 + lenInfo.bytesUsed;
  const valueEnd = valueStart + lenInfo.length;
  if (valueEnd > bytes.length) return null;
  return { tag, valueStart, valueEnd, next: valueEnd };
}

async function parseX509CertMetadataFromPem(pem?: string): Promise<{
  issuerOrg?: string;
  issuerCn?: string;
  sha256?: string;
}> {
  if (!pem || typeof pem !== 'string') return {};
  try {
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    if (!b64) return {};
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }

    let sha256: string | undefined;
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      try {
        const digest = await crypto.subtle.digest('SHA-256', bytes);
        sha256 = Array.from(new Uint8Array(digest))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      } catch {}
    }

    let issuerOrg: string | undefined;
    let issuerCn: string | undefined;

    const certSeq = readDerTlv(bytes, 0);
    const tbsSeq = certSeq ? readDerTlv(bytes, certSeq.valueStart) : null;
    if (tbsSeq) {
      let cursor = tbsSeq.valueStart;
      const firstField = readDerTlv(bytes, cursor);
      if (firstField && firstField.tag === 0xa0) cursor = firstField.next; // optional explicit [0] version
      const serial = readDerTlv(bytes, cursor);
      const sigAlg = serial ? readDerTlv(bytes, serial.next) : null;
      const issuer = sigAlg ? readDerTlv(bytes, sigAlg.next) : null;
      if (issuer && issuer.tag === 0x30) {
        const decoder = new TextDecoder();
        let rdnCursor = issuer.valueStart;
        while (rdnCursor < issuer.valueEnd) {
          const rdnSet = readDerTlv(bytes, rdnCursor);
          if (!rdnSet) break;
          let attrCursor = rdnSet.valueStart;
          while (attrCursor < rdnSet.valueEnd) {
            const attrSeq = readDerTlv(bytes, attrCursor);
            if (!attrSeq) break;
            const oidTlv = readDerTlv(bytes, attrSeq.valueStart);
            const valTlv = oidTlv ? readDerTlv(bytes, oidTlv.next) : null;
            if (oidTlv && valTlv && oidTlv.tag === 0x06) {
              const oid = bytes.subarray(oidTlv.valueStart, oidTlv.valueEnd);
              const valStr = decoder.decode(bytes.subarray(valTlv.valueStart, valTlv.valueEnd)).trim();
              if (oid.length === 3 && oid[0] === 0x55 && oid[1] === 0x04) {
                if (oid[2] === 10 && !issuerOrg && valStr) issuerOrg = valStr;
                if (oid[2] === 3 && !issuerCn && valStr) issuerCn = valStr;
              }
            }
            attrCursor = attrSeq.next;
          }
          rdnCursor = rdnSet.next;
        }
      }
    }

    return { issuerOrg, issuerCn, sha256 };
  } catch {
    return {};
  }
}

async function fetchBrowserTlsCertsViaCorsInspector(
  cleanApex: string,
  discoveredHosts: string[],
  subsSet: Set<string>,
  onWildcard: () => void
): Promise<CtCertificateEntry[]> {
  const probeTargets = prioritizeSubdomainsForRecon(cleanApex, discoveredHosts, 8)
    .filter((h) => !h.startsWith('*.'))
    .slice(0, 8);
  if (probeTargets.length === 0) return [];

  const results: CtCertificateEntry[] = [];
  let idx = 0;
  const concurrency = Math.min(4, probeTargets.length);

  const probeOne = async (host: string) => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      const res = await fetch(`https://networkcalc.com/api/security/certificate/${encodeURIComponent(host)}`, {
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) return;
      const json = await res.json();
      const cert = json?.certificate;
      if (!cert || json?.status !== 'OK') return;

      const sanList = new Set<string>();
      const rawAlt = Array.isArray(cert.alternate_names) ? cert.alternate_names : [];
      for (const rawName of rawAlt) {
        const cleaned = String(rawName)
          .replace(/^DNS:/i, '')
          .toLowerCase()
          .trim()
          .replace(/^\.+|\.+$/g, '');
        if (!cleaned) continue;
        if (cleaned.startsWith('*.')) onWildcard();
        const base = cleaned.startsWith('*.') ? cleaned.slice(2) : cleaned;
        if (base && (base === cleanApex || base.endsWith(`.${cleanApex}`))) {
          sanList.add(cleaned);
          subsSet.add(cleaned);
        }
      }
      if (sanList.size === 0 && (host === cleanApex || host.endsWith(`.${cleanApex}`))) {
        sanList.add(host);
        subsSet.add(host);
      }
      if (sanList.size === 0) return;

      const parsedPem = await parseX509CertMetadataFromPem(cert.raw);
      const fallbackFingerprint =
        typeof cert.fingerprint === 'string' && cert.fingerprint.trim()
          ? cert.fingerprint.replace(/:/g, '').toLowerCase()
          : undefined;
      const serial = typeof cert.serial_number === 'string' ? cert.serial_number.trim() : undefined;
      const sha256 = parsedPem.sha256 || fallbackFingerprint;

      results.push({
        id: serial || sha256 || `live-${host}`,
        issuerOrg: parsedPem.issuerOrg || (typeof cert.issued_by === 'string' ? cert.issued_by.trim() : undefined),
        issuerCn: parsedPem.issuerCn || (typeof cert.issued_by === 'string' ? cert.issued_by.trim() : undefined),
        notBefore: typeof cert.valid_from === 'string' ? cert.valid_from : undefined,
        notAfter: typeof cert.valid_to === 'string' ? cert.valid_to : undefined,
        revoked: false,
        sha256,
        dnsNames: Array.from(sanList).sort(),
      });
    } catch {}
  };

  const workers = Array.from({ length: concurrency }, async () => {
    while (idx < probeTargets.length) {
      const host = probeTargets[idx++];
      await probeOne(host);
    }
  });
  await Promise.all(workers);

  return results;
}

function parseClientIssuerDn(issuerDn: string): { issuerOrg?: string; issuerCn?: string } {
  const raw = String(issuerDn || '');
  const orgMatch = raw.match(/(?:^|,\s*)O=(?:"([^"]+)"|([^,]+))/);
  const cnMatch = raw.match(/(?:^|,\s*)CN=(?:"([^"]+)"|([^,]+))/);
  return {
    issuerOrg: (orgMatch?.[1] || orgMatch?.[2] || '').trim() || undefined,
    issuerCn: (cnMatch?.[1] || cnMatch?.[2] || '').trim() || undefined,
  };
}

function normalizeCrtShDate(val: unknown): string | undefined {
  if (typeof val !== 'string') return undefined;
  const trimmed = val.trim();
  if (!trimmed) return undefined;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(trimmed)) {
    return `${trimmed}Z`;
  }
  return trimmed;
}

const clientCrtShCache = new Map<
  string,
  { certs: CtCertificateEntry[]; subdomains: string[]; fetchedAt: number }
>();

function buildCertSemanticKey(cert: Pick<CtCertificateEntry, 'issuerOrg' | 'notBefore' | 'notAfter' | 'dnsNames'>): string {
  const nb = cert.notBefore ? cert.notBefore.slice(0, 10) : '';
  const na = cert.notAfter ? cert.notAfter.slice(0, 10) : '';
  return `${(cert.issuerOrg || '').toLowerCase()}|${nb}|${na}|${cert.dnsNames.join(',')}`;
}

function deduplicateAndSortCertificates(certs: CtCertificateEntry[], limit = 120): CtCertificateEntry[] {
  const bySha = new Map<string, CtCertificateEntry>();
  const bySemantic = new Map<string, CtCertificateEntry>();
  const merged: CtCertificateEntry[] = [];

  for (const cert of certs) {
    const shaKey = cert.sha256 ? cert.sha256.toLowerCase().trim() : '';
    const semanticKey = buildCertSemanticKey(cert);

    if (shaKey && bySha.has(shaKey)) continue;
    const existingSemantic = bySemantic.get(semanticKey);
    if (existingSemantic) {
      // Keep richer entry (one that already has sha256 or revoked status)
      if (!existingSemantic.sha256 && shaKey) {
        const idx = merged.indexOf(existingSemantic);
        if (idx !== -1) merged[idx] = cert;
        bySemantic.set(semanticKey, cert);
        bySha.set(shaKey, cert);
      }
      continue;
    }

    if (shaKey) bySha.set(shaKey, cert);
    bySemantic.set(semanticKey, cert);
    merged.push(cert);
  }

  return merged
    .sort((a, b) => {
      const tA = a.notBefore ? Date.parse(a.notBefore) || 0 : 0;
      const tB = b.notBefore ? Date.parse(b.notBefore) || 0 : 0;
      return tB - tA;
    })
    .slice(0, limit);
}

interface CrtShFetchResult {
  ok: boolean;
  certs: CtCertificateEntry[];
  subdomains: string[];
}

interface CrtShTracker {
  promise: Promise<CrtShFetchResult>;
  settled: boolean;
  result?: CrtShFetchResult;
  currentAttempt: number;
  setShouldPersistRetry: (val: boolean) => void;
  stop: () => void;
}

function createClientCrtShTracker(
  rootDomain: string,
  externalSignal?: AbortSignal,
  onAttempt?: (attempt: number) => void
): CrtShTracker {
  let persistRetry = false;
  let stopped = false;
  const stopController = new AbortController();
  let resolvePersistReady: ((val: boolean) => void) | null = null;
  const persistReadyPromise = new Promise<boolean>((resolve) => {
    resolvePersistReady = resolve;
  });

  const tracker: CrtShTracker = {
    promise: Promise.resolve({ ok: false, certs: [], subdomains: [] }),
    settled: false,
    currentAttempt: 1,
    setShouldPersistRetry: (val: boolean) => {
      persistRetry = val;
      if (resolvePersistReady) {
        resolvePersistReady(val);
        resolvePersistReady = null;
      }
    },
    stop: () => {
      if (stopped) return;
      stopped = true;
      persistRetry = false;
      if (resolvePersistReady) {
        resolvePersistReady(false);
        resolvePersistReady = null;
      }
      stopController.abort();
      if (!tracker.settled) {
        tracker.settled = true;
        tracker.result = { ok: false, certs: [], subdomains: [] };
      }
    },
  };

  tracker.promise = (async (): Promise<CrtShFetchResult> => {
    const cleanApex = (extractApexDomain(rootDomain) || rootDomain)
      .toLowerCase()
      .trim()
      .replace(/^\.+|\.+$/g, '');
    if (!cleanApex || !isValidDomainFormat(cleanApex)) {
      const empty: CrtShFetchResult = { ok: true, certs: [], subdomains: [] };
      tracker.settled = true;
      tracker.result = empty;
      return empty;
    }

    const cached = clientCrtShCache.get(cleanApex);
    if (cached && Date.now() - cached.fetchedAt < 10 * 60 * 1000) {
      const hit: CrtShFetchResult = { ok: true, certs: cached.certs, subdomains: cached.subdomains };
      tracker.settled = true;
      tracker.result = hit;
      return hit;
    }

    const INITIAL_ATTEMPTS = 3;
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${cleanApex}`)}&output=json`;

    const isAborted = () => stopped || Boolean(externalSignal?.aborted) || stopController.signal.aborted;

    const sleepAbortable = (ms: number) =>
      new Promise<void>((resolve) => {
        if (isAborted()) {
          resolve();
          return;
        }
        const onAbort = () => {
          clearTimeout(t);
          externalSignal?.removeEventListener('abort', onAbort);
          stopController.signal.removeEventListener('abort', onAbort);
          resolve();
        };
        const t = setTimeout(() => {
          externalSignal?.removeEventListener('abort', onAbort);
          stopController.signal.removeEventListener('abort', onAbort);
          resolve();
        }, ms);
        externalSignal?.addEventListener('abort', onAbort, { once: true });
        stopController.signal.addEventListener('abort', onAbort, { once: true });
      });

    let attempt = 1;
    while (!isAborted()) {
      tracker.currentAttempt = attempt;
      if (attempt > 1 && !isAborted()) {
        onAttempt?.(attempt);
      }

      const timeoutMs = Math.min(30000, 15000 + (attempt - 1) * 4000);
      const controller = new AbortController();
      const onExternalAbort = () => controller.abort();
      externalSignal?.addEventListener('abort', onExternalAbort, { once: true });
      stopController.signal.addEventListener('abort', onExternalAbort, { once: true });
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const res = await fetch(url, {
          headers: { Accept: 'application/json' },
          signal: controller.signal,
        });
        clearTimeout(timer);
        externalSignal?.removeEventListener('abort', onExternalAbort);
        stopController.signal.removeEventListener('abort', onExternalAbort);

        if (isAborted()) break;

        if (res.ok) {
          const text = await readBoundedResponseText(res, 3 * 1024 * 1024);
          const items = JSON.parse(text);
          if (Array.isArray(items)) {
            const parsedCerts: CtCertificateEntry[] = [];
            const subSet = new Set<string>();

            for (const item of items.slice(0, 300)) {
              const rawNames = String(item?.name_value || item?.common_name || '')
                .split(/[\r\n,]+/)
                .map((s) => s.trim())
                .filter(Boolean);
              const dnsSet = new Set<string>();
              for (const rawName of rawNames) {
                const cleaned = rawName.toLowerCase().replace(/^\.+|\.+$/g, '');
                if (!cleaned) continue;
                const base = cleaned.startsWith('*.') ? cleaned.slice(2) : cleaned;
                if (base && (base === cleanApex || base.endsWith(`.${cleanApex}`))) {
                  dnsSet.add(cleaned);
                  subSet.add(cleaned);
                }
              }
              if (dnsSet.size === 0) continue;

              const parsedDn = parseClientIssuerDn(String(item?.issuer_name || ''));
              parsedCerts.push({
                id: String(item?.id || parsedCerts.length + 1),
                issuerOrg: parsedDn.issuerOrg,
                issuerCn: parsedDn.issuerCn,
                notBefore: normalizeCrtShDate(item?.not_before),
                notAfter: normalizeCrtShDate(item?.not_after),
                dnsNames: Array.from(dnsSet).sort(),
              });
            }

            const certs = deduplicateAndSortCertificates(parsedCerts, 120);
            const subdomains = Array.from(subSet).sort();
            clientCrtShCache.set(cleanApex, { certs, subdomains, fetchedAt: Date.now() });
            const success: CrtShFetchResult = { ok: true, certs, subdomains };
            tracker.settled = true;
            tracker.result = success;
            return success;
          }
        }
      } catch {
        clearTimeout(timer);
        externalSignal?.removeEventListener('abort', onExternalAbort);
        stopController.signal.removeEventListener('abort', onExternalAbort);
      }

      if (isAborted()) break;

      if (attempt >= INITIAL_ATTEMPTS) {
        const shouldContinue = resolvePersistReady ? await persistReadyPromise : persistRetry;
        if (!shouldContinue || isAborted()) break;
      }

      const waitMs = Math.min(60000, 2000 * Math.pow(2, attempt - 1));
      await sleepAbortable(waitMs);
      attempt++;
    }

    const done: CrtShFetchResult = { ok: false, certs: [], subdomains: [] };
    tracker.settled = true;
    tracker.result = done;
    return done;
  })();

  return tracker;
}

function mergeCrtShDataIntoRecord(
  record: WhoisDomainRecord,
  crtShData: { certs: CtCertificateEntry[]; subdomains: string[] },
  nextStatus?: 'idle' | 'collecting' | 'complete',
  nextAttempt?: number
): { record: WhoisDomainRecord; changed: boolean } {
  const prevCerts = record.crtCertificates || [];
  const mergedCerts =
    crtShData.certs.length > 0
      ? deduplicateAndSortCertificates([...prevCerts, ...crtShData.certs], 120)
      : prevCerts;

  const prevSubs = record.crtSubdomainsSample || [];
  const mergedSubSet = new Set<string>(prevSubs);
  for (const s of crtShData.subdomains) {
    mergedSubSet.add(s);
  }
  const mergedSubs = Array.from(mergedSubSet).sort();
  const cappedSubs = mergedSubs.slice(0, 150);
  const nextCount = Math.max(record.crtSubdomainsCount || 0, mergedSubs.length);
  const nextWildcard = Boolean(record.crtWildcardFound || mergedSubs.some((s) => s.startsWith('*.')));

  const certsChanged =
    mergedCerts.length !== prevCerts.length ||
    mergedCerts.some((c, i) => prevCerts[i]?.id !== c.id || prevCerts[i]?.dnsNames.length !== c.dnsNames.length);
  const subsChanged =
    cappedSubs.length !== prevSubs.length || nextCount !== (record.crtSubdomainsCount || 0);
  const statusChanged =
    (nextStatus !== undefined && nextStatus !== record.crtShStatus) ||
    (nextAttempt !== undefined && nextAttempt !== record.crtShAttempt);

  if (!certsChanged && !subsChanged && !statusChanged) {
    return { record, changed: false };
  }

  const primaryCert = mergedCerts.find((c) => !c.revoked) || mergedCerts[0];
  return {
    changed: true,
    record: {
      ...record,
      crtCertificates: mergedCerts,
      crtSubdomainsSample: cappedSubs,
      crtSubdomainsCount: nextCount,
      crtWildcardFound: nextWildcard,
      crtShStatus: nextStatus ?? record.crtShStatus,
      crtShAttempt: nextAttempt ?? record.crtShAttempt,
      tlsIssuerOrg: record.tlsIssuerOrg || primaryCert?.issuerOrg,
      tlsIssuerCn: record.tlsIssuerCn || primaryCert?.issuerCn,
      tlsValidityNotBefore: record.tlsValidityNotBefore || primaryCert?.notBefore,
      tlsValidityNotAfter: record.tlsValidityNotAfter || primaryCert?.notAfter,
    },
  };
}

async function fetchClientCtSubdomains(
  rootDomain: string,
  seedSubdomains: string[] = []
): Promise<{
  crtSubdomainsCount: number;
  crtSubdomainsSample: string[];
  allSubdomains: string[];
  hackerTargetRecords: Array<{ host: string; ip: string }>;
  crtWildcardFound: boolean;
  crtCertificates: CtCertificateEntry[];
  tlsIssuerOrg?: string;
  tlsIssuerCn?: string;
  tlsValidityNotBefore?: string;
  tlsValidityNotAfter?: string;
}> {
  const cleanApex = (extractApexDomain(rootDomain) || rootDomain)
    .toLowerCase()
    .trim()
    .replace(/^\.+|\.+$/g, '');
  const subs = new Set<string>(
    seedSubdomains
      .map((s) => s.toLowerCase().trim().replace(/^\.+|\.+$/g, ''))
      .filter((s) => {
        const base = s.startsWith('*.') ? s.slice(2) : s;
        return Boolean(base) && (base === cleanApex || base.endsWith(`.${cleanApex}`));
      })
  );
  const hackerTargetRecords: Array<{ host: string; ip: string }> = [];
  const rawCerts: CtCertificateEntry[] = [];
  let crtWildcardFound = Array.from(subs).some((s) => s.startsWith('*.'));
  let tlsIssuerOrg: string | undefined;
  let tlsIssuerCn: string | undefined;
  let tlsValidityNotBefore: string | undefined;
  let tlsValidityNotAfter: string | undefined;

  const queryCrtName = async () => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      const res = await fetch(`https://crt.name/v1/search?apex=${encodeURIComponent(cleanApex)}`, {
        headers: { Accept: 'application/json, text/plain' },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) return;
      const text = await res.text();
      let items: string[] = [];
      try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
          items = parsed
            .map((entry: any) => (entry?.sub || entry?.name || (typeof entry === 'string' ? entry : '')).trim())
            .filter(Boolean);
        }
      } catch {
        items = text
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean);
      }
      for (const item of items.slice(0, 500)) {
        const cleaned = item.toLowerCase().replace(/\s+/g, '').replace(/^\.+|\.+$/g, '');
        if (!cleaned) continue;
        if (cleaned.startsWith('*.')) crtWildcardFound = true;
        const base = cleaned.startsWith('*.') ? cleaned.slice(2) : cleaned;
        if (base && (base === cleanApex || base.endsWith(`.${cleanApex}`))) {
          subs.add(cleaned);
        }
      }
    } catch {}
  };

  const queryCertspotter = async () => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(cleanApex)}&include_subdomains=true&expand=dns_names&expand=issuer`,
        { headers: { Accept: 'application/json' }, signal: controller.signal }
      );
      clearTimeout(timer);
      if (res.ok) {
        const items = await res.json();
        if (Array.isArray(items)) {
          const preferred = items.find((it: any) => it && !it.revoked && it.issuer) || items[0];
          if (preferred) {
            const parsedDn = parseClientIssuerDn(String(preferred.issuer?.name || ''));
            tlsIssuerOrg = parsedDn.issuerOrg || preferred.issuer?.friendly_name || undefined;
            tlsIssuerCn = parsedDn.issuerCn;
            if (preferred.not_before) tlsValidityNotBefore = String(preferred.not_before);
            if (preferred.not_after) tlsValidityNotAfter = String(preferred.not_after);
          }

          for (const item of items) {
            if (!Array.isArray(item?.dns_names)) continue;
            const certDnsSet = new Set<string>();
            for (const name of item.dns_names) {
              const cleaned = String(name).toLowerCase().trim().replace(/^\.+|\.+$/g, '');
              if (cleaned.startsWith('*.')) crtWildcardFound = true;
              const base = cleaned.startsWith('*.') ? cleaned.slice(2) : cleaned;
              if (base && (base === cleanApex || base.endsWith(`.${cleanApex}`))) {
                subs.add(cleaned);
                certDnsSet.add(cleaned);
              }
            }
            if (certDnsSet.size > 0) {
              const parsedDn = parseClientIssuerDn(String(item.issuer?.name || ''));
              const sha256 =
                typeof item.tbs_sha256 === 'string'
                  ? item.tbs_sha256
                  : typeof item.cert_sha256 === 'string'
                  ? item.cert_sha256
                  : undefined;

              rawCerts.push({
                id: String(item.id || sha256 || rawCerts.length + 1),
                issuerOrg:
                  parsedDn.issuerOrg ||
                  (typeof item.issuer?.friendly_name === 'string' ? item.issuer.friendly_name.trim() : undefined),
                issuerCn: parsedDn.issuerCn,
                notBefore: typeof item.not_before === 'string' ? item.not_before : undefined,
                notAfter: typeof item.not_after === 'string' ? item.not_after : undefined,
                revoked: Boolean(item.revoked),
                sha256,
                dnsNames: Array.from(certDnsSet).sort(),
              });
            }
          }
        }
      }
    } catch {}
  };

  const queryHackerTarget = async () => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      const res = await fetch(
        `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(cleanApex)}`,
        { signal: controller.signal }
      );
      clearTimeout(timer);
      if (res.ok) {
        const text = await res.text();
        if (text && !text.includes('error') && !text.includes('API count exceeded')) {
          for (const line of text.split('\n').slice(0, 500)) {
            const [hostRaw, ipRaw] = line.split(',');
            const host = hostRaw?.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
            const ip = ipRaw?.trim();
            if (host && (host === cleanApex || host.endsWith(`.${cleanApex}`))) {
              subs.add(host);
              if (ip) {
                hackerTargetRecords.push({ host, ip });
              }
            }
          }
        }
      }
    } catch {}
  };

  await Promise.all([queryCrtName(), queryCertspotter(), queryHackerTarget()]);

  // Fallback in pure browser JS when Certspotter is rate-limited/empty: inspect live leaf certificates via CORS TLS inspector
  if (rawCerts.length === 0) {
    const liveCerts = await fetchBrowserTlsCertsViaCorsInspector(
      cleanApex,
      Array.from(subs),
      subs,
      () => {
        crtWildcardFound = true;
      }
    );
    if (liveCerts.length > 0) {
      rawCerts.push(...liveCerts);
      const primaryCert = liveCerts[0];
      if (!tlsIssuerOrg && primaryCert.issuerOrg) tlsIssuerOrg = primaryCert.issuerOrg;
      if (!tlsIssuerCn && primaryCert.issuerCn) tlsIssuerCn = primaryCert.issuerCn;
      if (!tlsValidityNotBefore && primaryCert.notBefore) tlsValidityNotBefore = primaryCert.notBefore;
      if (!tlsValidityNotAfter && primaryCert.notAfter) tlsValidityNotAfter = primaryCert.notAfter;
    }
  }

  const sorted = Array.from(subs).sort();
  const crtCertificates = deduplicateAndSortCertificates(rawCerts, 80);

  return {
    crtSubdomainsCount: sorted.length,
    crtSubdomainsSample: sorted.slice(0, 120),
    allSubdomains: sorted,
    hackerTargetRecords,
    crtWildcardFound,
    crtCertificates,
    tlsIssuerOrg,
    tlsIssuerCn,
    tlsValidityNotBefore,
    tlsValidityNotAfter,
  };
}

async function fetchClientPassiveDns(
  cleanDomain: string,
  rootDomain: string,
  discoveredSubs: string[] = [],
  preloadedHtRecords: Array<{ host: string; ip: string }> = []
): Promise<{
  passiveDnsDisplay: string[];
  passiveDnsIps: string[];
  pdnsQueriedSubdomainsCount: number;
}> {
  const ipSet = new Set<string>();
  const displayMap = new Map<string, string>();
  const addPdnsDisplay = (rr: string, host: string, ans: string) => {
    const cleanRr = rr.toUpperCase().trim();
    const cleanHost = host.toLowerCase().trim().replace(/\.$/, '');
    const cleanAns = ans.trim();
    if (!cleanRr || !cleanHost || !cleanAns) return;
    const key = `${cleanRr}|${cleanHost}|${cleanAns.toLowerCase()}`;
    if (!displayMap.has(key)) {
      displayMap.set(key, `${cleanRr} | ${cleanHost} -> ${cleanAns}`);
    }
  };

  for (const rec of preloadedHtRecords) {
    if (!rec.host || !rec.ip) continue;
    if (/^[\da-fA-F:.]+$/.test(rec.ip)) ipSet.add(rec.ip);
    addPdnsDisplay(rec.ip.includes(':') ? 'AAAA' : 'A', rec.host, rec.ip);
  }

  const queryHackerTarget = async () => {
    if (preloadedHtRecords.length > 0) return;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      const res = await fetch(
        `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(rootDomain)}`,
        { signal: controller.signal }
      );
      clearTimeout(timer);
      if (!res.ok) return;
      const text = await res.text();
      if (!text || text.includes('error') || text.includes('API count exceeded')) return;
      for (const line of text.split('\n').slice(0, 500)) {
        const [hostRaw, ipRaw] = line.split(',');
        const host = hostRaw?.trim().toLowerCase();
        const ip = ipRaw?.trim();
        if (!host || !ip) continue;
        if (/^[\da-fA-F:.]+$/.test(ip)) ipSet.add(ip);
        addPdnsDisplay(ip.includes(':') ? 'AAAA' : 'A', host, ip);
      }
    } catch {}
  };

  const pdnsTargets = prioritizeSubdomainsForRecon(cleanDomain, discoveredSubs, 10);

  const queryRipeDnsChainForHost = async (targetHost: string) => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3200);
      const res = await fetch(
        `https://stat.ripe.net/data/dns-chain/data.json?resource=${encodeURIComponent(targetHost)}`,
        { headers: { Accept: 'application/json' }, signal: controller.signal }
      );
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

  const queryRipeBatched = async () => {
    const concurrency = 5;
    let idx = 0;
    const workers = Array.from({ length: Math.min(concurrency, pdnsTargets.length) }, async () => {
      while (idx < pdnsTargets.length) {
        const host = pdnsTargets[idx++];
        await queryRipeDnsChainForHost(host);
      }
    });
    await Promise.all(workers);
  };

  await Promise.all([queryHackerTarget(), queryRipeBatched()]);

  return {
    passiveDnsDisplay: Array.from(displayMap.values()).sort().slice(0, 250),
    passiveDnsIps: Array.from(ipSet).sort(),
    pdnsQueriedSubdomainsCount: pdnsTargets.length,
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

/**
 * Pure-browser zero-execution web reconnaissance across discovered subdomains when targets allow CORS.
 * Strictly reads bounded UTF-8 text and parses HTML in detached inert DOMParser;
 * NEVER executes fetched JS or injects HTML into the live DOM.
 */
async function probeClientWebPageAndHeaders(cleanDomain: string, discoveredSubs: string[] = []) {
  const candidates = prioritizeSubdomainsForRecon(cleanDomain, discoveredSubs, 8);
  const seenFinalUrls = new Set<string>();
  const seenScriptUrls = new Set<string>();
  const entries: SubdomainWebProbeEntry[] = [];
  let totalScriptFetches = 0;
  const deadline = Date.now() + 7000;

  const probeHost = async (host: string) => {
    if (Date.now() > deadline) return;
    const targetUrl = `https://${host}`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2800);
      const res = await fetch(targetUrl, {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
        headers: { Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8' },
        signal: controller.signal,
      });
      clearTimeout(timer);

      const sanitizedHeaders = sanitizeHttpHeaders(res.headers);
      const finalUrl = res.url || targetUrl;
      const dedupFinalUrl = normalizeFinalUrlForDedup(finalUrl);
      const serverHeader = sanitizedHeaders['server'] || undefined;

      if (seenFinalUrls.has(dedupFinalUrl)) {
        entries.push({
          host,
          httpWebServer: serverHeader,
          httpStatusCode: res.status,
          webFinalUrl: finalUrl,
        });
        try {
          await res.body?.cancel();
        } catch {}
        return;
      }
      seenFinalUrls.add(dedupFinalUrl);

      const htmlText = await readBoundedResponseText(res, MAX_HTML_RECON_BYTES);
      const recon = analyzeHtmlRecon(htmlText, finalUrl, sanitizedHeaders, host);

      let inspectedScriptsCount = 0;
      if (totalScriptFetches < 6 && Date.now() < deadline) {
        const remainingScripts = Math.min(2, 6 - totalScriptFetches);
        const candidateScripts = selectFirstPartyScriptsForInspection(recon.scriptUrls, host, remainingScripts * 2)
          .filter((sUrl) => {
            const normScript = normalizeFinalUrlForDedup(sUrl);
            if (seenScriptUrls.has(normScript)) return false;
            seenScriptUrls.add(normScript);
            return true;
          })
          .slice(0, remainingScripts);
        totalScriptFetches += candidateScripts.length;

        if (candidateScripts.length > 0) {
          const scriptTexts = await Promise.allSettled(
            candidateScripts.map(async (sUrl) => {
              const sc = new AbortController();
              const st = setTimeout(() => sc.abort(), 2000);
              try {
                const sr = await fetch(sUrl, {
                  method: 'GET',
                  mode: 'cors',
                  credentials: 'omit',
                  signal: sc.signal,
                });
                clearTimeout(st);
                if (!sr.ok) return null;
                return await readBoundedResponseText(sr, MAX_SCRIPT_TEXT_BYTES);
              } catch {
                clearTimeout(st);
                return null;
              }
            })
          );
          const analyticsSet = new Set<string>(recon.analyticsIds);
          for (const r of scriptTexts) {
            if (r.status === 'fulfilled' && r.value) {
              inspectedScriptsCount++;
              extractAnalyticsIdsFromText(r.value).forEach((id) => analyticsSet.add(id));
            }
          }
          recon.analyticsIds = Array.from(analyticsSet).sort();
        }
      }

      entries.push({
        host,
        httpWebServer: serverHeader,
        httpStatusCode: res.status,
        webFinalUrl: finalUrl,
        inspectedScriptsCount,
        recon,
      });
    } catch {}
  };

  let idx = 0;
  const concurrency = Math.min(4, candidates.length);
  const workers = Array.from({ length: concurrency }, async () => {
    while (idx < candidates.length && Date.now() < deadline) {
      const host = candidates[idx++];
      await probeHost(host);
    }
  });
  await Promise.all(workers);

  return mergeSubdomainWebRecon(cleanDomain, entries, candidates.length, 'browser-cors');
}

// Fallback Browser RDAP, DoH & OSINT Query (used on GitHub Pages static hosting or when backend is unavailable)
async function fetchClientSideWhois(domain: string): Promise<WhoisDomainRecord> {
  const clean = sanitizeDomainInput(domain);
  const root = extractApexDomain(clean) || clean;
  const tld = root.split('.').pop() || '';

  let rdapData: any = null;
  let rawText = '';
  let registrar = 'Protected / Redacted';
  let createdDate: string | undefined;
  let updatedDate: string | undefined;
  let expiresDate: string | undefined;
  let abuseContactEmail: string | undefined;
  let registrantCountry: string | undefined;
  let registrantState: string | undefined;
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

  // Phase 1: RDAP, DoH DNS, and CT/HackerTarget subdomain discovery
  const [, nsRes, aRes, aaaaRes, mxRes, dsRes, ctData] = await Promise.all([
    fetchRdap(),
    queryBrowserDoh(clean, 'NS'),
    queryBrowserDoh(clean, 'A'),
    queryBrowserDoh(clean, 'AAAA'),
    queryBrowserDoh(clean, 'MX'),
    queryBrowserDoh(root, 'DS'),
    fetchClientCtSubdomains(root),
  ]);

  // Phase 2: Search all discovered subdomains for Passive DNS & Web Recon
  const [pdnsData, webData] = await Promise.all([
    fetchClientPassiveDns(clean, root, ctData.allSubdomains, ctData.hackerTargetRecords),
    probeClientWebPageAndHeaders(clean, ctData.allSubdomains),
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
    domainName: clean,
    rootDomain: root,
    source: rdapData ? 'rdap' : 'doh',
    registrar,
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
    dnsProvider: inferDnsProvider(nameservers),
    aRecords,
    aaaaRecords,
    mailProvider: inferClientMailProvider(mxRecords),
    asn: asnInfo.asn,
    asnName: asnInfo.asnName,
    subnet24: asnInfo.subnet24,
    passiveDnsDisplay: pdnsData.passiveDnsDisplay,
    passiveDnsIps: pdnsData.passiveDnsIps,
    pdnsQueriedSubdomainsCount: pdnsData.pdnsQueriedSubdomainsCount,
    tlsIssuerOrg: ctData.tlsIssuerOrg,
    tlsIssuerCn: ctData.tlsIssuerCn,
    tlsValidityNotBefore: ctData.tlsValidityNotBefore,
    tlsValidityNotAfter: ctData.tlsValidityNotAfter,
    crtSubdomainsCount: ctData.crtSubdomainsCount,
    crtSubdomainsSample: ctData.crtSubdomainsSample,
    crtWildcardFound: ctData.crtWildcardFound,
    crtCertificates: ctData.crtCertificates,
    htmlVerificationTokens: webData.htmlVerificationTokens || [],
    analyticsIds: webData.analyticsIds || [],
    footerCopyrights: webData.footerCopyrights || [],
    copyrightEntities: webData.copyrightEntities || [],
    httpWebServer: webData.httpWebServer,
    httpStatusCode: webData.httpStatusCode,
    httpHeaderSummary: webData.httpHeaderSummary || [],
    cspExternalDomains: webData.cspExternalDomains || [],
    webReconMode: webData.webReconMode,
    webFinalUrl: webData.webFinalUrl,
    inspectedScriptsCount: webData.inspectedScriptsCount || 0,
    webReconProbedHostsCount: webData.webReconProbedHostsCount,
    webReconReachableHosts: webData.webReconReachableHosts || [],
    htmlTitle: webData.htmlTitle,
    htmlDescription: webData.htmlDescription,
    htmlGenerator: webData.htmlGenerator,
    htmlAuthor: webData.htmlAuthor,
    htmlRobots: webData.htmlRobots,
    canonicalUrl: webData.canonicalUrl,
    openGraphSiteName: webData.openGraphSiteName,
    twitterSite: webData.twitterSite,
    domMarkers: webData.domMarkers || [],
    domStats: webData.domStats,
    scriptUrls: webData.scriptUrls || [],
    resourceSummary: webData.resourceSummary || [],
    technologies: webData.technologies || [],
    externalDomains: webData.externalDomains || [],
    registrantOrg,
    registrantCountry,
    registrantState,
    abuseContactEmail,
    rawText,
  };
}

async function enrichClientCertsIfMissing(record: WhoisDomainRecord): Promise<WhoisDomainRecord> {
  if (record.crtCertificates && record.crtCertificates.length > 0) {
    return record;
  }
  try {
    const ctFallback = await fetchClientCtSubdomains(
      record.rootDomain || record.domainName,
      record.crtSubdomainsSample || []
    );
    if (ctFallback.crtCertificates.length === 0) {
      return record;
    }
    const mergedSubs = Array.from(
      new Set([...(record.crtSubdomainsSample || []), ...ctFallback.crtSubdomainsSample])
    ).sort();
    return {
      ...record,
      crtCertificates: ctFallback.crtCertificates,
      crtSubdomainsSample: mergedSubs.slice(0, 120),
      crtSubdomainsCount: Math.max(record.crtSubdomainsCount || 0, ctFallback.crtSubdomainsCount, mergedSubs.length),
      crtWildcardFound: Boolean(record.crtWildcardFound || ctFallback.crtWildcardFound),
      tlsIssuerOrg: record.tlsIssuerOrg || ctFallback.tlsIssuerOrg,
      tlsIssuerCn: record.tlsIssuerCn || ctFallback.tlsIssuerCn,
      tlsValidityNotBefore: record.tlsValidityNotBefore || ctFallback.tlsValidityNotBefore,
      tlsValidityNotAfter: record.tlsValidityNotAfter || ctFallback.tlsValidityNotAfter,
    };
  } catch {
    return record;
  }
}

async function fetchDomainWhois(domain: string): Promise<WhoisDomainRecord> {
  const clean = sanitizeDomainInput(domain);
  if (!isValidDomainFormat(clean)) {
    throw new Error('Invalid or disallowed domain syntax. Please enter a valid public domain name.');
  }

  if (shouldUseBackendApi()) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 24000);
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
          const enriched = await enrichDomainWithBrowserDns(data as WhoisDomainRecord);
          return enrichClientCertsIfMissing(enriched);
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

export async function fetchAndCompareWhois(
  domainA: string,
  domainB?: string,
  onUpdate?: (updatedResult: WhoisDiffResult) => void,
  signal?: AbortSignal
): Promise<WhoisDiffResult> {
  const cleanA = sanitizeDomainInput(domainA || '');
  const cleanB = sanitizeDomainInput(domainB || '');

  if (cleanA && !isValidDomainFormat(cleanA)) {
    throw new Error('Domain A is not a valid public domain name.');
  }
  if (cleanB && !isValidDomainFormat(cleanB)) {
    throw new Error('Domain B is not a valid public domain name.');
  }
  if (!cleanA && !cleanB) {
    throw new Error('At least one valid public domain name is required.');
  }

  // Single-domain OSINT reconnaissance mode when only one domain is provided
  if (!cleanA || !cleanB) {
    const singleDomain = cleanA || cleanB;
    let latestRecord: WhoisDomainRecord | null = null;

    const crtShTracker = createClientCrtShTracker(singleDomain, signal, (attempt) => {
      if (!latestRecord || !onUpdate || signal?.aborted) return;
      const { record: updated, changed } = mergeCrtShDataIntoRecord(
        latestRecord,
        { certs: [], subdomains: [] },
        'collecting',
        attempt
      );
      if (changed) {
        latestRecord = updated;
        onUpdate(computeSingleDomainResult(latestRecord));
      }
    });

    const record = await fetchDomainWhois(singleDomain);
    const hasRetrievedCertData = (record.crtCertificates?.length || 0) > 0;

    if (hasRetrievedCertData) {
      const resolvedData =
        crtShTracker.settled && crtShTracker.result
          ? crtShTracker.result
          : { certs: [], subdomains: [] };
      crtShTracker.stop();
      const { record: merged } = mergeCrtShDataIntoRecord(
        record,
        resolvedData,
        'complete',
        crtShTracker.currentAttempt
      );
      return computeSingleDomainResult(merged);
    }

    crtShTracker.setShouldPersistRetry((record.crtSubdomainsCount || 0) > 0);

    if (crtShTracker.settled && crtShTracker.result) {
      const { record: merged } = mergeCrtShDataIntoRecord(record, crtShTracker.result, 'complete', crtShTracker.currentAttempt);
      return computeSingleDomainResult(merged);
    }

    latestRecord = {
      ...record,
      crtShStatus: 'collecting',
      crtShAttempt: crtShTracker.currentAttempt,
    };

    if (onUpdate && !signal?.aborted) {
      void crtShTracker.promise.then((crtShData) => {
        if (signal?.aborted || !latestRecord) return;
        const { record: merged, changed } = mergeCrtShDataIntoRecord(
          latestRecord,
          crtShData,
          'complete',
          crtShTracker.currentAttempt
        );
        if (changed) {
          latestRecord = merged;
          onUpdate(computeSingleDomainResult(latestRecord));
        }
      });
    }

    return computeSingleDomainResult(latestRecord);
  }

  let latestA: WhoisDomainRecord | null = null;
  let latestB: WhoisDomainRecord | null = null;

  const emitPairUpdate = (nextA: WhoisDomainRecord, nextB: WhoisDomainRecord, changed: boolean) => {
    if (!onUpdate || signal?.aborted || !changed) return;
    latestA = nextA;
    latestB = nextB;
    onUpdate(computeWhoisDiff(latestA, latestB));
  };

  // Kick off crt.sh queries in parallel so initial UI prepopulates immediately with crt.name/fast sources
  const crtShTrackerA = createClientCrtShTracker(cleanA, signal, (attempt) => {
    if (!latestA || !latestB) return;
    const { record: nextA, changed } = mergeCrtShDataIntoRecord(
      latestA,
      { certs: [], subdomains: [] },
      'collecting',
      attempt
    );
    emitPairUpdate(nextA, latestB, changed);
  });
  const crtShTrackerB = createClientCrtShTracker(cleanB, signal, (attempt) => {
    if (!latestA || !latestB) return;
    const { record: nextB, changed } = mergeCrtShDataIntoRecord(
      latestB,
      { certs: [], subdomains: [] },
      'collecting',
      attempt
    );
    emitPairUpdate(latestA, nextB, changed);
  });

  let baseRecordA: WhoisDomainRecord | null = null;
  let baseRecordB: WhoisDomainRecord | null = null;

  // Try server-side consolidated diff endpoint when backend is available, then enrich with pure browser-JS DoH lookups
  if (shouldUseBackendApi()) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30000);
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
            enrichDomainWithBrowserDns(data.domainA as WhoisDomainRecord).then(enrichClientCertsIfMissing),
            enrichDomainWithBrowserDns(data.domainB as WhoisDomainRecord).then(enrichClientCertsIfMissing),
          ]);
          baseRecordA = enrichedA;
          baseRecordB = enrichedB;
        }
      } else if (res.status === 404 || res.status === 405 || !ct.includes('application/json')) {
        backendApiAvailable = false;
      }
    } catch {}
  }

  if (!baseRecordA || !baseRecordB) {
    const [recordA, recordB] = await Promise.all([
      fetchDomainWhois(cleanA),
      fetchDomainWhois(cleanB),
    ]);
    baseRecordA = recordA;
    baseRecordB = recordB;
  }

  const hasCertDataA = (baseRecordA.crtCertificates?.length || 0) > 0;
  const hasCertDataB = (baseRecordB.crtCertificates?.length || 0) > 0;

  if (hasCertDataA) {
    const resolvedA =
      crtShTrackerA.settled && crtShTrackerA.result
        ? crtShTrackerA.result
        : { certs: [], subdomains: [] };
    crtShTrackerA.stop();
    baseRecordA = mergeCrtShDataIntoRecord(baseRecordA, resolvedA, 'complete', crtShTrackerA.currentAttempt).record;
  } else {
    crtShTrackerA.setShouldPersistRetry((baseRecordA.crtSubdomainsCount || 0) > 0);
    if (crtShTrackerA.settled && crtShTrackerA.result) {
      baseRecordA = mergeCrtShDataIntoRecord(baseRecordA, crtShTrackerA.result, 'complete', crtShTrackerA.currentAttempt).record;
    } else {
      baseRecordA = { ...baseRecordA, crtShStatus: 'collecting', crtShAttempt: crtShTrackerA.currentAttempt };
    }
  }

  if (hasCertDataB) {
    const resolvedB =
      crtShTrackerB.settled && crtShTrackerB.result
        ? crtShTrackerB.result
        : { certs: [], subdomains: [] };
    crtShTrackerB.stop();
    baseRecordB = mergeCrtShDataIntoRecord(baseRecordB, resolvedB, 'complete', crtShTrackerB.currentAttempt).record;
  } else {
    crtShTrackerB.setShouldPersistRetry((baseRecordB.crtSubdomainsCount || 0) > 0);
    if (crtShTrackerB.settled && crtShTrackerB.result) {
      baseRecordB = mergeCrtShDataIntoRecord(baseRecordB, crtShTrackerB.result, 'complete', crtShTrackerB.currentAttempt).record;
    } else {
      baseRecordB = { ...baseRecordB, crtShStatus: 'collecting', crtShAttempt: crtShTrackerB.currentAttempt };
    }
  }

  latestA = baseRecordA;
  latestB = baseRecordB;

  if (onUpdate && !signal?.aborted) {
    if (!crtShTrackerA.settled && !hasCertDataA) {
      void crtShTrackerA.promise.then((crtShA) => {
        if (!latestA || !latestB) return;
        const { record: nextA, changed } = mergeCrtShDataIntoRecord(
          latestA,
          crtShA,
          'complete',
          crtShTrackerA.currentAttempt
        );
        emitPairUpdate(nextA, latestB, changed);
      });
    }
    if (!crtShTrackerB.settled && !hasCertDataB) {
      void crtShTrackerB.promise.then((crtShB) => {
        if (!latestA || !latestB) return;
        const { record: nextB, changed } = mergeCrtShDataIntoRecord(
          latestB,
          crtShB,
          'complete',
          crtShTrackerB.currentAttempt
        );
        emitPairUpdate(latestA, nextB, changed);
      });
    }
  }

  return computeWhoisDiff(baseRecordA, baseRecordB);
}
