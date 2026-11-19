// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useMemo, useRef, useEffect, useCallback, useLayoutEffect } from 'react';
import { WhoisDiffResult, WhoisDomainRecord } from '../types';

interface OsintTopologyMapProps {
  diff: WhoisDiffResult;
}

interface TopologyNode {
  id: string;
  label: string;
  sublabel: string;
  type: 'domainA' | 'domainB' | 'shared' | 'uniqueA' | 'uniqueB';
  category: 'core' | 'network' | 'dns' | 'mail' | 'cert' | 'registrar' | 'token';
  x: number;
  y: number;
}

interface TopologyLink {
  from: string;
  to: string;
  isShared: boolean;
  label?: string;
}

interface PopupFieldRow {
  label: string;
  value: string;
}

interface NodePopupDetails {
  badge: string;
  title: string;
  subtitle?: string;
  rows: PopupFieldRow[];
}

const CANVAS_WIDTH = 1120;
const NODE_WIDTH = 164;
const NODE_HEIGHT = 66;
const ROW_GAP = 18;
const ROW_STEP = NODE_HEIGHT + ROW_GAP;
const TOP_PAD = 36;
const POPUP_MARGIN = 12;

const COL_X = {
  uniqueA: 16,
  domainA: 247,
  shared: 478,
  domainB: 709,
  uniqueB: 940,
} as const;

const REDUNDANT_SUBLABELS = new Set([
  'REGISTRAR',
  'SHARED REGISTRAR',
  'SHARED BGP ASN',
  'UPSTREAM ASN',
  'CO-LOCATED /24',
  'SHARED MAIL MX',
  'MAIL GATEWAY',
  'SHARED TXT PROOF',
  'SHARED ANALYTICS ID',
  'SHARED COPYRIGHT HOLDER',
  'SHARED PDNS IP',
  'SHARED EXTERNAL ORIGIN',
  'SSL SUBJECT ORG',
  'SHARED PTR HOSTNAME',
  'SHARED SPF ORIGIN IP',
  'SHARED SOA RNAME',
  'SHARED DMARC REPORT',
  'SHARED DKIM TENANT',
  'DNS CLUSTER',
]);

function getNodeKindLabel(n: TopologyNode): string {
  if (n.category === 'core') return 'DOMAIN';
  if (n.category === 'registrar') return 'REGISTRAR';
  if (n.category === 'cert') return 'TLS CERTIFICATE';
  if (n.id === 'shared_analytics') return 'ANALYTICS ID';
  if (n.id === 'shared_copyright') return 'COPYRIGHT HOLDER';
  if (n.category === 'token') return 'TXT VERIFICATION';
  if (n.id === 'shared_subnet') return 'IP SUBNET /24';
  if (n.id === 'shared_pdns_ip') return 'PASSIVE DNS IP';
  if (n.id === 'shared_ptr') return 'PTR HOSTNAME';
  if (n.id === 'shared_spf_ip') return 'SPF ORIGIN IP';
  if (n.category === 'network') return 'BGP ASN';
  if (n.id === 'shared_soa_rname') return 'SOA CONTACT';
  if (n.id === 'shared_ext_domain') return 'EXTERNAL ORIGIN';
  if (n.category === 'dns') return 'NAMESERVER';
  if (n.id === 'shared_dmarc') return 'DMARC REPORT';
  if (n.id === 'shared_dkim') return 'DKIM TENANT';
  if (n.category === 'mail') return 'MAIL PROVIDER';
  return 'INDICATOR';
}

function formatList(items: string[] | undefined): string | null {
  if (!items || items.length === 0) return null;
  const cleaned = items.map((s) => s.trim()).filter(Boolean);
  if (cleaned.length === 0) return null;
  return cleaned.join('\n');
}

function appendDomainNetworkRows(
  rows: PopupFieldRow[],
  labelPrefix: string,
  rec: WhoisDomainRecord,
  options: { includeSubnet?: boolean; includePtr?: boolean } = {}
) {
  const ips = formatList([...(rec.aRecords || []), ...(rec.aaaaRecords || [])]);
  if (ips) rows.push({ label: `${labelPrefix} IPs`, value: ips });
  if (options.includeSubnet && rec.subnet24) {
    rows.push({ label: `${labelPrefix} /24`, value: rec.subnet24 });
  }
  if (options.includePtr) {
    const ptrs = formatList(rec.ptrHostnames);
    if (ptrs) rows.push({ label: `${labelPrefix} PTR`, value: ptrs });
  }
}

function buildNodePopupDetails(node: TopologyNode, diff: WhoisDiffResult): NodePopupDetails {
  const { domainA, domainB, summary } = diff;
  const isSingle = Boolean(diff.isSingleDomain || !domainB);
  const kind = getNodeKindLabel(node);
  const rows: PopupFieldRow[] = [];

  const hasSubnetNode = Boolean((isSingle || summary.sameSubnet24) && domainA.subnet24);
  const hasPtrNode = Boolean(summary.sharedPtrHostnames && summary.sharedPtrHostnames.length > 0);
  const hasTlsNode = Boolean((isSingle || summary.sameTlsSubjectOrg) && domainA.tlsSubjectOrg);

  const buildDomainOverview = (rec: WhoisDomainRecord): PopupFieldRow[] => {
    const out: PopupFieldRow[] = [];
    if (rec.createdDate || rec.domainAgeFormatted) {
      out.push({
        label: 'Inception',
        value: [rec.createdDate, rec.domainAgeFormatted ? `(${rec.domainAgeFormatted})` : ''].filter(Boolean).join(' '),
      });
    }
    if (rec.expiresDate) {
      out.push({
        label: 'Expiration',
        value: rec.daysUntilExpiration !== undefined
          ? `${rec.expiresDate} (${rec.daysUntilExpiration}d)`
          : rec.expiresDate,
      });
    }
    if (!rec.asn && !hasSubnetNode) {
      const ipv4 = formatList(rec.aRecords);
      if (ipv4) out.push({ label: 'IPv4 (A)', value: ipv4 });
      const ipv6 = formatList(rec.aaaaRecords);
      if (ipv6) out.push({ label: 'IPv6 (AAAA)', value: ipv6 });
    }
    out.push({ label: 'DNSSEC', value: rec.dnssec.toUpperCase() });
    if (!hasTlsNode && (rec.tlsSubjectOrg || rec.tlsIssuerOrg)) {
      out.push({
        label: 'TLS Cert',
        value: [rec.tlsSubjectOrg, rec.tlsIssuerOrg ? `Issuer: ${rec.tlsIssuerOrg}` : ''].filter(Boolean).join(' | '),
      });
    }
    if (rec.httpWebServer || rec.httpStatusCode) {
      out.push({
        label: 'HTTP Surface',
        value: [rec.httpStatusCode ? `HTTP ${rec.httpStatusCode}` : '', rec.httpWebServer].filter(Boolean).join(' — '),
      });
    }
    if (typeof rec.crtSubdomainsCount === 'number' && rec.crtSubdomainsCount > 0) {
      out.push({ label: 'CT Subdomains', value: `${rec.crtSubdomainsCount} observed` });
    }
    return out;
  };

  if (node.id === 'domA') {
    rows.push(...buildDomainOverview(domainA));
  } else if (node.id === 'domB' && domainB) {
    rows.push(...buildDomainOverview(domainB));
  } else if (node.id === 'shared_asn' && domainB) {
    const opts = { includeSubnet: !hasSubnetNode, includePtr: !hasPtrNode };
    appendDomainNetworkRows(rows, domainA.domainName, domainA, opts);
    appendDomainNetworkRows(rows, domainB.domainName, domainB, opts);
  } else if (node.id === 'asn_a' || (node.id === 'asn_b' && domainB)) {
    const rec = node.id === 'asn_a' ? domainA : domainB!;
    appendDomainNetworkRows(rows, rec.domainName, rec, {
      includeSubnet: !hasSubnetNode,
      includePtr: !hasPtrNode,
    });
  } else if (node.id === 'subnet_a') {
    if (domainA.asn) {
      rows.push({ label: 'ASN', value: domainA.asnName ? `${domainA.asn} (${domainA.asnName})` : domainA.asn });
    }
    appendDomainNetworkRows(rows, domainA.domainName, domainA, { includePtr: true });
  } else if (node.id === 'tls_a') {
    if (domainA.tlsSubjectCn && domainA.tlsSubjectCn !== node.label) {
      rows.push({ label: 'Subject CN', value: domainA.tlsSubjectCn });
    }
    if (domainA.tlsIssuerOrg || domainA.tlsIssuerCn) {
      rows.push({ label: 'Issuer', value: domainA.tlsIssuerOrg || domainA.tlsIssuerCn || '' });
    }
    if (domainA.tlsProtocol || domainA.tlsCipher) {
      rows.push({
        label: 'Handshake',
        value: [domainA.tlsProtocol, domainA.tlsCipher].filter(Boolean).join(' / '),
      });
    }
    if (domainA.tlsValidityNotBefore || domainA.tlsValidityNotAfter) {
      rows.push({
        label: 'Validity',
        value: `${domainA.tlsValidityNotBefore || '?'} -> ${domainA.tlsValidityNotAfter || '?'}`,
      });
    }
  } else if (node.id === 'shared_subnet' && domainB) {
    if (!summary.sameAsn && domainA.asn && domainB.asn) {
      rows.push({
        label: 'ASNs',
        value: `${domainA.domainName}: ${domainA.asn}\n${domainB.domainName}: ${domainB.asn}`,
      });
    }
    appendDomainNetworkRows(rows, domainA.domainName, domainA, { includePtr: !hasPtrNode });
    appendDomainNetworkRows(rows, domainB.domainName, domainB, { includePtr: !hasPtrNode });
  } else if (node.id === 'shared_ns' && domainB) {
    const setNsB = new Set(domainB.nameservers.map((s) => s.toLowerCase()));
    const sharedNs = domainA.nameservers.filter((s) => setNsB.has(s.toLowerCase()));
    const sharedLower = new Set(sharedNs.map((s) => s.toLowerCase()));
    const allSharedNs = formatList(sharedNs);
    if (allSharedNs) {
      rows.push({ label: 'Shared NS', value: allSharedNs });
    }
    const extraA = formatList(domainA.nameservers.filter((s) => !sharedLower.has(s.toLowerCase())));
    const extraB = formatList(domainB.nameservers.filter((s) => !sharedLower.has(s.toLowerCase())));
    if (extraA) rows.push({ label: `${domainA.domainName} Unique NS`, value: extraA });
    if (extraB) rows.push({ label: `${domainB.domainName} Unique NS`, value: extraB });
    if (domainA.dnsProvider) rows.push({ label: 'DNS Provider', value: domainA.dnsProvider });
  } else if (node.id === 'ns_a' || (node.id === 'ns_b' && domainB)) {
    const rec = node.id === 'ns_a' ? domainA : domainB!;
    if (rec.nameservers.length > 1) {
      const allNs = formatList(rec.nameservers);
      if (allNs) rows.push({ label: 'Nameservers', value: allNs });
    }
    if (rec.soaMname) rows.push({ label: 'SOA Primary', value: rec.soaMname });
    if (rec.soaSerial) rows.push({ label: 'SOA Serial', value: rec.soaSerial });
  } else if (node.id === 'shared_mail' && domainB) {
    if (domainA.spfRecord) rows.push({ label: `${domainA.domainName} SPF`, value: domainA.spfRecord });
    if (domainB.spfRecord) rows.push({ label: `${domainB.domainName} SPF`, value: domainB.spfRecord });
    if (domainA.dmarcPolicy || domainB.dmarcPolicy) {
      rows.push({
        label: 'DMARC Policy',
        value: `${domainA.domainName}: ${domainA.dmarcPolicy || 'none'}\n${domainB.domainName}: ${domainB.dmarcPolicy || 'none'}`,
      });
    }
  } else if (node.id === 'mail_a' || (node.id === 'mail_b' && domainB)) {
    const rec = node.id === 'mail_a' ? domainA : domainB!;
    if (rec.spfRecord) rows.push({ label: 'SPF Record', value: rec.spfRecord });
    if (rec.dmarcPolicy) rows.push({ label: 'DMARC Policy', value: rec.dmarcPolicy });
    const dkim = formatList(rec.dkimSelectors);
    if (dkim) rows.push({ label: 'DKIM Selectors', value: dkim });
  } else if (node.id === 'shared_tokens' && domainB) {
    const tokensA = [...(domainA.verificationTokens || []), ...(domainA.htmlVerificationTokens || [])];
    const tokensB = new Set(
      [...(domainB.verificationTokens || []), ...(domainB.htmlVerificationTokens || [])].map(
        (t) => `${t.provider.toLowerCase()}::${t.token.toLowerCase()}`
      )
    );
    const matched = tokensA.filter((t) => tokensB.has(`${t.provider.toLowerCase()}::${t.token.toLowerCase()}`));
    const uniqueMatched = Array.from(new Map(matched.map((t) => [`${t.provider}:${t.token}`, t])).values());
    uniqueMatched.forEach((t) => {
      rows.push({ label: t.provider, value: t.token });
    });
  } else if (node.id === 'shared_analytics' && domainB) {
    if ((summary.sharedAnalyticsIds || []).length > 1) {
      const allShared = formatList(summary.sharedAnalyticsIds);
      if (allShared) rows.push({ label: 'Shared IDs', value: allShared });
    }
    const sharedSet = new Set((summary.sharedAnalyticsIds || []).map((id) => id.toLowerCase()));
    const uniqA = formatList((domainA.analyticsIds || []).filter((id) => !sharedSet.has(id.toLowerCase())));
    const uniqB = formatList((domainB.analyticsIds || []).filter((id) => !sharedSet.has(id.toLowerCase())));
    if (uniqA) rows.push({ label: `${domainA.domainName} Unique`, value: uniqA });
    if (uniqB) rows.push({ label: `${domainB.domainName} Unique`, value: uniqB });
  } else if (node.id === 'shared_copyright' && domainB) {
    if ((summary.sharedCopyrightEntities || []).length > 1) {
      const allShared = formatList(summary.sharedCopyrightEntities);
      if (allShared) rows.push({ label: 'Shared Entities', value: allShared });
    }
    const cA = formatList(domainA.footerCopyrights);
    const cB = formatList(domainB.footerCopyrights);
    if (cA) rows.push({ label: domainA.domainName, value: cA });
    if (cB) rows.push({ label: domainB.domainName, value: cB });
  } else if (node.id === 'shared_pdns_ip' && domainB) {
    if ((summary.sharedPassiveDnsIps || []).length > 1) {
      const allShared = formatList(summary.sharedPassiveDnsIps);
      if (allShared) rows.push({ label: 'Shared PDNS IPs', value: allShared });
    }
    const pdA = formatList(domainA.passiveDnsDisplay);
    const pdB = formatList(domainB.passiveDnsDisplay);
    if (pdA) rows.push({ label: domainA.domainName, value: pdA });
    if (pdB) rows.push({ label: domainB.domainName, value: pdB });
  } else if (node.id === 'shared_ext_domain' && domainB) {
    if ((summary.sharedExternalDomains || []).length > 1) {
      const allShared = formatList(summary.sharedExternalDomains);
      if (allShared) rows.push({ label: 'Shared Origins', value: allShared });
    }
    rows.push({
      label: 'Total External',
      value: `${domainA.domainName}: ${domainA.externalDomains?.length || 0}\n${domainB.domainName}: ${domainB.externalDomains?.length || 0}`,
    });
  } else if (node.id === 'shared_tls_org' && domainB) {
    if (domainA.tlsSubjectCn && domainA.tlsSubjectCn !== node.label) {
      rows.push({ label: `${domainA.domainName} CN`, value: domainA.tlsSubjectCn });
    }
    if (domainB.tlsSubjectCn && domainB.tlsSubjectCn !== node.label) {
      rows.push({ label: `${domainB.domainName} CN`, value: domainB.tlsSubjectCn });
    }
    if (domainA.tlsIssuerOrg || domainA.tlsIssuerCn) {
      rows.push({ label: 'Issuer', value: domainA.tlsIssuerOrg || domainA.tlsIssuerCn || '' });
    }
    if (domainA.tlsProtocol || domainA.tlsCipher) {
      rows.push({
        label: 'Handshake',
        value: [domainA.tlsProtocol, domainA.tlsCipher].filter(Boolean).join(' / '),
      });
    }
    if (domainA.tlsValidityNotBefore || domainA.tlsValidityNotAfter) {
      rows.push({
        label: 'Validity',
        value: `${domainA.tlsValidityNotBefore || '?'} -> ${domainA.tlsValidityNotAfter || '?'}`,
      });
    }
  } else if (node.id === 'shared_ptr' && domainB) {
    if ((summary.sharedPtrHostnames || []).length > 1) {
      const allShared = formatList(summary.sharedPtrHostnames);
      if (allShared) rows.push({ label: 'Shared PTRs', value: allShared });
    }
    appendDomainNetworkRows(rows, domainA.domainName, domainA);
    appendDomainNetworkRows(rows, domainB.domainName, domainB);
  } else if (node.id === 'shared_spf_ip' && domainB) {
    if ((summary.sharedSpfIps || []).length > 1) {
      const allShared = formatList(summary.sharedSpfIps);
      if (allShared) rows.push({ label: 'Shared SPF IPs', value: allShared });
    }
    if (domainA.spfRecord) rows.push({ label: `${domainA.domainName} SPF`, value: domainA.spfRecord });
    if (domainB.spfRecord) rows.push({ label: `${domainB.domainName} SPF`, value: domainB.spfRecord });
  } else if (node.id === 'shared_soa_rname' && domainB) {
    if (domainA.soaMname) {
      rows.push({
        label: domainA.domainName,
        value: `${domainA.soaMname}${domainA.soaSerial ? ` (serial ${domainA.soaSerial})` : ''}`,
      });
    }
    if (domainB.soaMname) {
      rows.push({
        label: domainB.domainName,
        value: `${domainB.soaMname}${domainB.soaSerial ? ` (serial ${domainB.soaSerial})` : ''}`,
      });
    }
  } else if (node.id === 'shared_dmarc' && domainB) {
    if (domainA.dmarcRua && domainA.dmarcRua !== node.label) {
      rows.push({ label: 'Aggregate (RUA)', value: domainA.dmarcRua });
    }
    if (domainA.dmarcRuf && domainA.dmarcRuf !== node.label) {
      rows.push({ label: 'Forensic (RUF)', value: domainA.dmarcRuf });
    }
    rows.push({
      label: 'Policies',
      value: `${domainA.domainName}: ${domainA.dmarcPolicy || 'none'}\n${domainB.domainName}: ${domainB.dmarcPolicy || 'none'}`,
    });
  } else if (node.id === 'shared_dkim' && domainB) {
    if ((summary.sharedDkimTargets || []).length > 1) {
      const allShared = formatList(summary.sharedDkimTargets);
      if (allShared) rows.push({ label: 'Shared Targets', value: allShared });
    }
    const selA = formatList(domainA.dkimSelectors);
    const selB = formatList(domainB.dkimSelectors);
    if (selA) rows.push({ label: `${domainA.domainName} Selectors`, value: selA });
    if (selB) rows.push({ label: `${domainB.domainName} Selectors`, value: selB });
  } else if (node.id === 'shared_registrar' && domainB) {
    if (domainA.abuseContactEmail) rows.push({ label: 'Abuse Email', value: domainA.abuseContactEmail });
    const stA = formatList(domainA.status);
    const stB = formatList(domainB.status);
    if (stA) rows.push({ label: `${domainA.domainName} Status`, value: stA });
    if (stB) rows.push({ label: `${domainB.domainName} Status`, value: stB });
  } else if (node.id === 'reg_a' || (node.id === 'reg_b' && domainB)) {
    const rec = node.id === 'reg_a' ? domainA : domainB!;
    if (rec.abuseContactEmail) rows.push({ label: 'Abuse Email', value: rec.abuseContactEmail });
    if (rec.registrantOrg) rows.push({ label: 'Registrant Org', value: rec.registrantOrg });
    if (rec.registrantCountry) rows.push({ label: 'Country', value: rec.registrantCountry });
    const st = formatList(rec.status);
    if (st) rows.push({ label: 'EPP Status', value: st });
  }

  const badgePrefix =
    node.type === 'domainA'
      ? isSingle ? 'TARGET' : 'TARGET A'
      : node.type === 'domainB'
      ? 'TARGET B'
      : node.type === 'shared'
      ? 'SHARED HUB'
      : node.type === 'uniqueA'
      ? `${domainA.domainName}`
      : `${domainB?.domainName || ''}`;

  const normSub = node.sublabel.trim().toUpperCase();
  const normKind = kind.trim().toUpperCase();
  const normLabel = node.label.trim().toUpperCase();
  const includeSub =
    node.id !== 'shared_ns' &&
    Boolean(normSub) &&
    normSub !== normKind &&
    normSub.replace(/^SHARED\s+/, '') !== normKind &&
    normSub !== normLabel &&
    !REDUNDANT_SUBLABELS.has(normSub);

  return {
    badge: `${badgePrefix} // ${kind}`,
    title: node.label,
    subtitle: includeSub ? node.sublabel : undefined,
    rows,
  };
}

export const OsintTopologyMap: React.FC<OsintTopologyMapProps> = ({ diff }) => {
  const { domainA, domainB, summary } = diff;
  const isSingle = Boolean(diff.isSingleDomain || !domainB);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<'all' | 'shared' | 'network' | 'dns'>('all');
  const [view, setView] = useState<{ zoom: number; x: number; y: number }>({ zoom: 1, x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [vpSize, setVpSize] = useState<{ width: number; height: number }>({ width: 0, height: 0 });
  const [popupHeight, setPopupHeight] = useState<number>(280);

  const viewportRef = useRef<HTMLDivElement | null>(null);
  const popupRef = useRef<HTMLDivElement | null>(null);
  const canvasHeightRef = useRef<number>(300);
  const hasInteractedRef = useRef<boolean>(false);
  const suppressClickRef = useRef<boolean>(false);
  const dragRef = useRef<{
    active: boolean;
    startX: number;
    startY: number;
    lastX: number;
    lastY: number;
    moved: boolean;
  }>({ active: false, startX: 0, startY: 0, lastX: 0, lastY: 0, moved: false });

  // Compute unpositioned nodes and links first, then assign clean non-overlapping coordinates
  const { nodes, links, canvasHeight } = useMemo(() => {
    type RawNode = Omit<TopologyNode, 'x' | 'y'>;
    const rawNodes: RawNode[] = [];
    const linkList: TopologyLink[] = [];

    // Core Domain Nodes
    rawNodes.push({
      id: 'domA',
      label: domainA.domainName,
      sublabel: domainA.source.toUpperCase(),
      type: 'domainA',
      category: 'core',
    });

    if (domainB && !isSingle) {
      rawNodes.push({
        id: 'domB',
        label: domainB.domainName,
        sublabel: domainB.source.toUpperCase(),
        type: 'domainB',
        category: 'core',
      });
    }

    const setNsB = domainB ? new Set(domainB.nameservers.map((s) => s.toLowerCase())) : new Set<string>();
    const sharedNsList = domainB && !isSingle
      ? domainA.nameservers.filter((s) => setNsB.has(s.toLowerCase()))
      : [];

    const isRedactedRegA = !domainA.registrar || domainA.registrar === 'Protected / Redacted';
    const isSharedRegistrar = Boolean(domainB && !isSingle && summary.sameRegistrar && !isRedactedRegA);

    if (domainB && !isSingle) {
      // CENTER HUBS: Shared Infrastructure
      if (summary.sameAsn && domainA.asn) {
        const id = 'shared_asn';
        rawNodes.push({
          id,
          label: domainA.asn,
          sublabel: domainA.asnName || 'SHARED BGP ASN',
          type: 'shared',
          category: 'network',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'BGP' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'BGP' });
      }

      if (summary.sameSubnet24 && domainA.subnet24) {
        const id = 'shared_subnet';
        rawNodes.push({
          id,
          label: domainA.subnet24,
          sublabel: 'CO-LOCATED /24',
          type: 'shared',
          category: 'network',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: '/24' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: '/24' });
      }

      if (sharedNsList.length > 0) {
        const id = 'shared_ns';
        rawNodes.push({
          id,
          label: `${sharedNsList.length} Shared NS`,
          sublabel: sharedNsList[0],
          type: 'shared',
          category: 'dns',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'DNS' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'DNS' });
      }

      if (summary.sameMailProvider && domainA.mailProvider && domainA.mailProvider !== 'No MX Records Listed') {
        const id = 'shared_mail';
        rawNodes.push({
          id,
          label: domainA.mailProvider.split('(')[0].trim(),
          sublabel: 'SHARED MAIL MX',
          type: 'shared',
          category: 'mail',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'MX' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'MX' });
      }

      if (summary.sharedVerificationTokensCount > 0) {
        const id = 'shared_tokens';
        rawNodes.push({
          id,
          label: `${summary.sharedVerificationTokensCount} IDP Tokens`,
          sublabel: 'SHARED TXT PROOF',
          type: 'shared',
          category: 'token',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'TXT' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'TXT' });
      }

      if (summary.sharedAnalyticsIds && summary.sharedAnalyticsIds.length > 0) {
        const id = 'shared_analytics';
        rawNodes.push({
          id,
          label: summary.sharedAnalyticsIds[0],
          sublabel: 'SHARED ANALYTICS ID',
          type: 'shared',
          category: 'token',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'TAG' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'TAG' });
      }

      if (summary.sharedCopyrightEntities && summary.sharedCopyrightEntities.length > 0) {
        const id = 'shared_copyright';
        rawNodes.push({
          id,
          label: summary.sharedCopyrightEntities[0],
          sublabel: 'SHARED COPYRIGHT HOLDER',
          type: 'shared',
          category: 'token',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: '©' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: '©' });
      }

      if (summary.sharedPassiveDnsIps && summary.sharedPassiveDnsIps.length > 0) {
        const id = 'shared_pdns_ip';
        rawNodes.push({
          id,
          label: summary.sharedPassiveDnsIps[0],
          sublabel: 'SHARED PDNS IP',
          type: 'shared',
          category: 'network',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'PDNS' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'PDNS' });
      }

      if (summary.sharedExternalDomains && summary.sharedExternalDomains.length > 0) {
        const id = 'shared_ext_domain';
        rawNodes.push({
          id,
          label: summary.sharedExternalDomains[0],
          sublabel: 'SHARED EXTERNAL ORIGIN',
          type: 'shared',
          category: 'dns',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'EXT' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'EXT' });
      }

      if (summary.sameTlsSubjectOrg && domainA.tlsSubjectOrg) {
        const id = 'shared_tls_org';
        rawNodes.push({
          id,
          label: domainA.tlsSubjectOrg,
          sublabel: 'SSL SUBJECT ORG',
          type: 'shared',
          category: 'cert',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'TLS' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'TLS' });
      }

      if (summary.sharedPtrHostnames && summary.sharedPtrHostnames.length > 0) {
        const id = 'shared_ptr';
        rawNodes.push({
          id,
          label: summary.sharedPtrHostnames[0],
          sublabel: 'SHARED PTR HOSTNAME',
          type: 'shared',
          category: 'network',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'PTR' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'PTR' });
      }

      if (summary.sharedSpfIps && summary.sharedSpfIps.length > 0) {
        const id = 'shared_spf_ip';
        rawNodes.push({
          id,
          label: summary.sharedSpfIps[0],
          sublabel: 'SHARED SPF ORIGIN IP',
          type: 'shared',
          category: 'network',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'SPF' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'SPF' });
      }

      if (summary.sameSoaRname && domainA.soaRname) {
        const id = 'shared_soa_rname';
        rawNodes.push({
          id,
          label: domainA.soaRname,
          sublabel: 'SHARED SOA RNAME',
          type: 'shared',
          category: 'dns',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'SOA' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'SOA' });
      }

      if ((summary.sameDmarcRua || summary.sameDmarcRuf) && (domainA.dmarcRuf || domainA.dmarcRua)) {
        const id = 'shared_dmarc';
        rawNodes.push({
          id,
          label: domainA.dmarcRuf || domainA.dmarcRua || '',
          sublabel: 'SHARED DMARC REPORT',
          type: 'shared',
          category: 'mail',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'DMARC' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'DMARC' });
      }

      if (summary.sharedDkimTargets && summary.sharedDkimTargets.length > 0) {
        const id = 'shared_dkim';
        rawNodes.push({
          id,
          label: summary.sharedDkimTargets[0],
          sublabel: 'SHARED DKIM TENANT',
          type: 'shared',
          category: 'mail',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'DKIM' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'DKIM' });
      }

      if (isSharedRegistrar) {
        const id = 'shared_registrar';
        rawNodes.push({
          id,
          label: domainA.registrar,
          sublabel: 'SHARED REGISTRAR',
          type: 'shared',
          category: 'registrar',
        });
        linkList.push({ from: 'domA', to: id, isShared: true, label: 'REG' });
        linkList.push({ from: 'domB', to: id, isShared: true, label: 'REG' });
      }
    }

    // FLANKING NODES: Domain A (Left Column in dual, Right-of-core in single)
    if ((isSingle || !summary.sameAsn) && domainA.asn) {
      const id = 'asn_a';
      rawNodes.push({
        id,
        label: domainA.asn,
        sublabel: domainA.asnName || 'UPSTREAM ASN',
        type: 'uniqueA',
        category: 'network',
      });
      linkList.push({ from: 'domA', to: id, isShared: false, label: 'BGP' });
    }

    if (isSingle && domainA.subnet24) {
      const id = 'subnet_a';
      rawNodes.push({
        id,
        label: domainA.subnet24,
        sublabel: domainA.aRecords[0] || 'IPv4 PREFIX',
        type: 'uniqueA',
        category: 'network',
      });
      linkList.push({ from: 'domA', to: id, isShared: false, label: '/24' });
    }

    if (!isSharedRegistrar && domainA.registrar) {
      const idRegA = 'reg_a';
      rawNodes.push({
        id: idRegA,
        label: domainA.registrar,
        sublabel: 'REGISTRAR',
        type: 'uniqueA',
        category: 'registrar',
      });
      linkList.push({ from: 'domA', to: idRegA, isShared: false, label: 'REG' });
    }

    const sharedNsLower = new Set(sharedNsList.map((s) => s.toLowerCase()));
    if (domainA.nameservers.length > 0 && !sharedNsLower.has(domainA.nameservers[0].toLowerCase())) {
      const idNsA = 'ns_a';
      rawNodes.push({
        id: idNsA,
        label: domainA.nameservers[0],
        sublabel: domainA.dnsProvider || 'DNS CLUSTER',
        type: 'uniqueA',
        category: 'dns',
      });
      linkList.push({ from: 'domA', to: idNsA, isShared: false, label: 'DNS' });
    }

    if ((isSingle || !summary.sameMailProvider) && domainA.mailProvider && domainA.mailProvider !== 'No MX Records Listed') {
      const idMailA = 'mail_a';
      rawNodes.push({
        id: idMailA,
        label: domainA.mailProvider.split('(')[0].trim(),
        sublabel: 'MAIL GATEWAY',
        type: 'uniqueA',
        category: 'mail',
      });
      linkList.push({ from: 'domA', to: idMailA, isShared: false, label: 'MX' });
    }

    if (isSingle && domainA.tlsSubjectOrg) {
      const idTlsA = 'tls_a';
      rawNodes.push({
        id: idTlsA,
        label: domainA.tlsSubjectOrg,
        sublabel: domainA.tlsIssuerOrg || 'TLS CERTIFICATE',
        type: 'uniqueA',
        category: 'cert',
      });
      linkList.push({ from: 'domA', to: idTlsA, isShared: false, label: 'TLS' });
    }

    // FLANKING NODES: Domain B Unique (Right Column)
    if (domainB && !isSingle) {
      if (!summary.sameAsn && domainB.asn) {
        const id = 'asn_b';
        rawNodes.push({
          id,
          label: domainB.asn,
          sublabel: domainB.asnName || 'UPSTREAM ASN',
          type: 'uniqueB',
          category: 'network',
        });
        linkList.push({ from: 'domB', to: id, isShared: false, label: 'BGP' });
      }

      if (!isSharedRegistrar && domainB.registrar) {
        const idRegB = 'reg_b';
        rawNodes.push({
          id: idRegB,
          label: domainB.registrar,
          sublabel: 'REGISTRAR',
          type: 'uniqueB',
          category: 'registrar',
        });
        linkList.push({ from: 'domB', to: idRegB, isShared: false, label: 'REG' });
      }

      if (domainB.nameservers.length > 0 && !sharedNsLower.has(domainB.nameservers[0].toLowerCase())) {
        const idNsB = 'ns_b';
        rawNodes.push({
          id: idNsB,
          label: domainB.nameservers[0],
          sublabel: domainB.dnsProvider || 'DNS CLUSTER',
          type: 'uniqueB',
          category: 'dns',
        });
        linkList.push({ from: 'domB', to: idNsB, isShared: false, label: 'DNS' });
      }

      if (!summary.sameMailProvider && domainB.mailProvider && domainB.mailProvider !== 'No MX Records Listed') {
        const idMailB = 'mail_b';
        rawNodes.push({
          id: idMailB,
          label: domainB.mailProvider.split('(')[0].trim(),
          sublabel: 'MAIL GATEWAY',
          type: 'uniqueB',
          category: 'mail',
        });
        linkList.push({ from: 'domB', to: idMailB, isShared: false, label: 'MX' });
      }
    }

    // Filter active nodes first so columns pack and center cleanly per filter
    const effectiveFilter = isSingle && activeFilter === 'shared' ? 'all' : activeFilter;
    const visibleRaw = rawNodes.filter((n) => {
      if (effectiveFilter === 'all') return true;
      if (effectiveFilter === 'shared') return n.type === 'shared' || n.type === 'domainA' || n.type === 'domainB';
      if (effectiveFilter === 'network') return n.category === 'network' || n.type === 'domainA' || n.type === 'domainB';
      if (effectiveFilter === 'dns') return n.category === 'dns' || n.type === 'domainA' || n.type === 'domainB';
      return true;
    });

    const colUniqueA = visibleRaw.filter((n) => n.type === 'uniqueA');
    const colShared = visibleRaw.filter((n) => n.type === 'shared');
    const colUniqueB = visibleRaw.filter((n) => n.type === 'uniqueB');
    const colDomA = visibleRaw.filter((n) => n.type === 'domainA');
    const colDomB = visibleRaw.filter((n) => n.type === 'domainB');

    const maxColCount = Math.max(1, colUniqueA.length, colShared.length, colUniqueB.length);
    const computedHeight = Math.max(300, TOP_PAD * 2 + maxColCount * NODE_HEIGHT + (maxColCount - 1) * ROW_GAP);

    const placeColumn = (items: RawNode[], x: number): TopologyNode[] => {
      if (items.length === 0) return [];
      const colHeight = items.length * NODE_HEIGHT + (items.length - 1) * ROW_GAP;
      const startY = Math.round((computedHeight - colHeight) / 2);
      return items.map((item, idx) => ({
        ...item,
        x,
        y: startY + idx * ROW_STEP,
      }));
    };

    const positionedNodes: TopologyNode[] = isSingle
      ? [
          ...placeColumn(colDomA, 345),
          ...placeColumn(colUniqueA, 611),
        ]
      : [
          ...placeColumn(colUniqueA, COL_X.uniqueA),
          ...placeColumn(colDomA, COL_X.domainA),
          ...placeColumn(colShared, COL_X.shared),
          ...placeColumn(colDomB, COL_X.domainB),
          ...placeColumn(colUniqueB, COL_X.uniqueB),
        ];

    return {
      nodes: positionedNodes,
      links: linkList,
      canvasHeight: computedHeight,
    };
  }, [domainA, domainB, summary, activeFilter, isSingle]);

  const selectedNode = useMemo(() => {
    return nodes.find((n) => n.id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  const nodeMap = useMemo(() => {
    const map = new Map<string, TopologyNode>();
    nodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [nodes]);

  const popupDetails = useMemo(() => {
    if (!selectedNode) return null;
    return buildNodePopupDetails(selectedNode, diff);
  }, [selectedNode, diff]);

  const hasSharedVisible = useMemo(() => nodes.some((n) => n.type === 'shared'), [nodes]);

  const viewportHeight = Math.max(360, canvasHeight + 48);
  canvasHeightRef.current = canvasHeight;

  const clampView = useCallback((nextX: number, nextY: number, nextZoom: number) => {
    const el = viewportRef.current;
    const clampedZoom = Math.min(2.2, Math.max(0.4, nextZoom));
    if (!el) return { zoom: clampedZoom, x: nextX, y: nextY };

    const vpWidth = el.clientWidth;
    const vpHeight = el.clientHeight;
    const scaledW = CANVAS_WIDTH * clampedZoom;
    const scaledH = canvasHeightRef.current * clampedZoom;

    const minX = Math.min(0, vpWidth - scaledW);
    const maxX = Math.max(0, vpWidth - scaledW);
    const minY = Math.min(0, vpHeight - scaledH);
    const maxY = Math.max(0, vpHeight - scaledH);

    return {
      zoom: clampedZoom,
      x: Math.min(maxX, Math.max(minX, nextX)),
      y: Math.min(maxY, Math.max(minY, nextY)),
    };
  }, []);

  const centerView = useCallback(() => {
    const el = viewportRef.current;
    if (!el) return;
    const width = el.clientWidth;
    const height = el.clientHeight || viewportHeight;
    const fitZoom =
      width > 0 && width < CANVAS_WIDTH + 32
        ? Math.max(0.5, +((width - 32) / CANVAS_WIDTH).toFixed(2))
        : 1;
    const x = Math.round((width - CANVAS_WIDTH * fitZoom) / 2);
    const y = Math.round((height - canvasHeight * fitZoom) / 2);
    setView(clampView(x, y, fitZoom));
  }, [canvasHeight, viewportHeight, clampView]);

  useEffect(() => {
    if (isSingle && activeFilter === 'shared') {
      setActiveFilter('all');
    }
    hasInteractedRef.current = false;
    setSelectedNodeId(null);
    centerView();
  }, [domainA.domainName, domainB?.domainName, isSingle, activeFilter, centerView]);

  useEffect(() => {
    if (!selectedNodeId) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectedNodeId(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedNodeId]);

  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;
    const syncSize = () => {
      setVpSize({ width: el.clientWidth, height: el.clientHeight });
    };
    syncSize();
    const observer = new ResizeObserver(() => {
      syncSize();
      if (!hasInteractedRef.current) {
        centerView();
      } else {
        setView((prev) => clampView(prev.x, prev.y, prev.zoom));
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [centerView, clampView]);

  useLayoutEffect(() => {
    if (!popupRef.current) return;
    setPopupHeight(popupRef.current.offsetHeight);
  }, [popupDetails, vpSize]);

  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;

    const handleWheel = (e: WheelEvent) => {
      if (popupRef.current && popupRef.current.contains(e.target as Node)) {
        return;
      }
      e.preventDefault();
      hasInteractedRef.current = true;
      const rect = el.getBoundingClientRect();
      const cursorX = e.clientX - rect.left;
      const cursorY = e.clientY - rect.top;
      const delta = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
      const zoomFactor = Math.exp(-delta * 0.0015);

      setView((prev) => {
        const nextZoom = Math.min(2.2, Math.max(0.4, +(prev.zoom * zoomFactor).toFixed(3)));
        const ratio = nextZoom / prev.zoom;
        const nextX = cursorX - (cursorX - prev.x) * ratio;
        const nextY = cursorY - (cursorY - prev.y) * ratio;
        return clampView(nextX, nextY, nextZoom);
      });
    };

    el.addEventListener('wheel', handleWheel, { passive: false });
    return () => el.removeEventListener('wheel', handleWheel);
  }, [clampView]);

  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      if (!dragRef.current.active) return;
      const totalDx = e.clientX - dragRef.current.startX;
      const totalDy = e.clientY - dragRef.current.startY;
      const stepX = e.clientX - dragRef.current.lastX;
      const stepY = e.clientY - dragRef.current.lastY;
      dragRef.current.lastX = e.clientX;
      dragRef.current.lastY = e.clientY;

      if (!dragRef.current.moved && Math.hypot(totalDx, totalDy) > 4) {
        dragRef.current.moved = true;
        suppressClickRef.current = true;
        hasInteractedRef.current = true;
      }
      if (dragRef.current.moved) {
        setView((prev) => clampView(prev.x + stepX, prev.y + stepY, prev.zoom));
      }
    };

    const handlePointerUp = () => {
      if (!dragRef.current.active) return;
      dragRef.current.active = false;
      setIsDragging(false);
    };

    window.addEventListener('pointermove', handlePointerMove);
    window.addEventListener('pointerup', handlePointerUp);
    window.addEventListener('pointercancel', handlePointerUp);
    return () => {
      window.removeEventListener('pointermove', handlePointerMove);
      window.removeEventListener('pointerup', handlePointerUp);
      window.removeEventListener('pointercancel', handlePointerUp);
    };
  }, [clampView]);

  const handleViewportPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    suppressClickRef.current = false;
    dragRef.current = {
      active: true,
      startX: e.clientX,
      startY: e.clientY,
      lastX: e.clientX,
      lastY: e.clientY,
      moved: false,
    };
    setIsDragging(true);
  };

  const handleViewportClick = () => {
    if (suppressClickRef.current) {
      suppressClickRef.current = false;
      return;
    }
    setSelectedNodeId(null);
  };

  const handleResetView = () => {
    hasInteractedRef.current = false;
    centerView();
  };

  const handleNodeClick = (e: React.MouseEvent, node: TopologyNode) => {
    e.stopPropagation();
    if (suppressClickRef.current) {
      suppressClickRef.current = false;
      return;
    }
    setSelectedNodeId((prev) => (prev === node.id ? null : node.id));
  };

  const popupLayout = useMemo(() => {
    if (!selectedNode) return null;
    const widthVp = vpSize.width || 640;
    const heightVp = vpSize.height || viewportHeight;
    const popupWidth = Math.min(340, Math.max(240, widthVp - POPUP_MARGIN * 2));
    const maxHeight = Math.max(180, heightVp - POPUP_MARGIN * 2);

    const nodeLeft = view.x + selectedNode.x * view.zoom;
    const nodeRight = view.x + (selectedNode.x + NODE_WIDTH) * view.zoom;
    const nodeTop = view.y + selectedNode.y * view.zoom;

    let left: number;
    const preferLeftFirst = selectedNode.type === 'domainB' || selectedNode.type === 'uniqueB';
    const rightCandidate = nodeRight + 12;
    const leftCandidate = nodeLeft - popupWidth - 12;

    if (preferLeftFirst) {
      if (leftCandidate >= POPUP_MARGIN) {
        left = leftCandidate;
      } else if (rightCandidate + popupWidth <= widthVp - POPUP_MARGIN) {
        left = rightCandidate;
      } else {
        left = Math.round((widthVp - popupWidth) / 2);
      }
    } else {
      if (rightCandidate + popupWidth <= widthVp - POPUP_MARGIN) {
        left = rightCandidate;
      } else if (leftCandidate >= POPUP_MARGIN) {
        left = leftCandidate;
      } else {
        left = Math.round((widthVp - popupWidth) / 2);
      }
    }

    left = Math.max(POPUP_MARGIN, Math.min(widthVp - popupWidth - POPUP_MARGIN, left));
    const effectiveH = Math.min(popupHeight, maxHeight);
    const maxTop = Math.max(POPUP_MARGIN, heightVp - effectiveH - POPUP_MARGIN);
    const top = Math.max(POPUP_MARGIN, Math.min(maxTop, Math.round(nodeTop)));

    return {
      left,
      top,
      width: popupWidth,
      maxHeight,
    };
  }, [selectedNode, vpSize, viewportHeight, view, popupHeight]);

  const popupBorderAccent = useMemo(() => {
    if (!selectedNode) return 'border-[#383838]';
    if (selectedNode.type === 'domainA' || selectedNode.type === 'uniqueA') return 'border-[#c30800]';
    if (selectedNode.type === 'domainB' || selectedNode.type === 'uniqueB') return 'border-[#c300bb]';
    return 'border-[#c36a00]';
  }, [selectedNode]);

  const popupBadgeAccent = useMemo(() => {
    if (!selectedNode) return 'text-[#8c8c8c]';
    if (selectedNode.type === 'domainA' || selectedNode.type === 'uniqueA') return 'text-[#c30800]';
    if (selectedNode.type === 'domainB' || selectedNode.type === 'uniqueB') return 'text-[#c300bb]';
    return 'text-[#bbc300]';
  }, [selectedNode]);

  return (
    <div id="infrastructure-topology-map" className="bg-[#141414] border border-[#383838] rounded-none overflow-hidden flex flex-col relative z-0 isolate mb-6">
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Minimal Control & Legend Toolbar */}
      <div className="px-4 py-2.5 bg-[#141414] flex flex-wrap items-center justify-between gap-3 border-b border-[#383838]">
        <div className="flex flex-wrap items-center gap-1.5">
          {[
            { id: 'all', label: 'All Nodes' },
            ...(!isSingle ? [{ id: 'shared', label: 'Shared Hubs' }] : []),
            { id: 'network', label: 'BGP / Network' },
            { id: 'dns', label: 'DNS / Nameservers' },
          ].map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setActiveFilter(f.id as 'all' | 'shared' | 'network' | 'dns')}
              className={`px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer transition-colors font-semibold shrink-0 ${
                activeFilter === f.id
                  ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                  : 'bg-[#0d0d0d] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0] hover:border-[#383838]'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={handleResetView}
            className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider border border-[#383838] bg-[#141414] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer font-semibold"
            title="Reset topology view"
          >
            RESET VIEW
          </button>
        </div>
      </div>

      {/* Interactive Pan & Zoom Canvas Viewport */}
      <div
        ref={viewportRef}
        onPointerDown={handleViewportPointerDown}
        onClick={handleViewportClick}
        onDoubleClick={handleResetView}
        style={{ height: `${viewportHeight}px` }}
        className={`bg-[#0d0d0d] overflow-hidden relative select-none touch-none ${
          isDragging ? 'cursor-grabbing' : 'cursor-grab'
        }`}
      >
        <div
          style={{
            width: `${CANVAS_WIDTH}px`,
            height: `${canvasHeight}px`,
            transform: `translate(${view.x}px, ${view.y}px) scale(${view.zoom})`,
            transformOrigin: '0 0',
          }}
          className="relative"
        >
            <svg
              width={CANVAS_WIDTH}
              height={canvasHeight}
              viewBox={`0 0 ${CANVAS_WIDTH} ${canvasHeight}`}
              className="absolute inset-0 pointer-events-none"
            >
              {/* Edge-to-Edge Cubic Bezier Links */}
              {links.map((link, idx) => {
                const fromNode = nodeMap.get(link.from);
                const toNode = nodeMap.get(link.to);
                if (!fromNode || !toNode) return null;

                const isSelected = selectedNodeId === link.from || selectedNodeId === link.to;
                const goRight = toNode.x > fromNode.x;

                const x1 = goRight ? fromNode.x + NODE_WIDTH : fromNode.x;
                const y1 = fromNode.y + NODE_HEIGHT / 2;
                const x2 = goRight ? toNode.x : toNode.x + NODE_WIDTH;
                const y2 = toNode.y + NODE_HEIGHT / 2;
                const cx = (x1 + x2) / 2;
                const my = (y1 + y2) / 2;

                const pathD = `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`;
                const strokeColor = link.isShared
                  ? isSelected
                    ? '#bbc300'
                    : '#c36a00'
                  : link.from === 'domA'
                  ? '#c30800'
                  : '#c300bb';

                return (
                  <g key={idx}>
                    <path
                      d={pathD}
                      fill="none"
                      stroke={strokeColor}
                      strokeWidth={isSelected ? 2 : link.isShared ? 1.5 : 1.25}
                      strokeDasharray={link.isShared ? 'none' : '4 3'}
                      strokeOpacity={isSelected ? 1 : link.isShared ? 0.8 : 0.55}
                    />
                    <rect x={x1 - 2} y={y1 - 2} width={4} height={4} fill={strokeColor} />
                    <rect x={x2 - 2} y={y2 - 2} width={4} height={4} fill={strokeColor} />
                    {link.label && (
                      <g>
                        <rect
                          x={cx - 18}
                          y={my - 7}
                          width={36}
                          height={14}
                          fill="#0d0d0d"
                        />
                        <text
                          x={cx}
                          y={my + 3}
                          fill={isSelected ? '#f0f0f0' : '#8c8c8c'}
                          fontSize="8.5"
                          fontFamily="Fira Code, monospace"
                          textAnchor="middle"
                          className="select-none"
                        >
                          {link.label}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}
            </svg>

            {/* Empty Shared Column Indicator */}
            {!isSingle && !hasSharedVisible && (
              <div
                style={{
                  position: 'absolute',
                  left: `${COL_X.shared}px`,
                  top: `${Math.round((canvasHeight - NODE_HEIGHT) / 2)}px`,
                  width: `${NODE_WIDTH}px`,
                  height: `${NODE_HEIGHT}px`,
                }}
                className="border border-dashed border-[#2e2e2e] bg-[#111111] flex flex-col items-center justify-center px-2 text-center select-none z-10"
              >
                <span className="font-mono text-[10px] font-bold text-[#737373] uppercase">
                  No Shared Nodes
                </span>
                <span className="font-mono text-[9px] text-[#737373]/80 mt-0.5">
                  Isolated infra
                </span>
              </div>
            )}

            {/* Render Nodes */}
            {nodes.map((node) => {
              const kindLabel = getNodeKindLabel(node);
              const normSub = node.sublabel.trim().toUpperCase();
              const normKind = kindLabel.trim().toUpperCase();
              const normLabel = node.label.trim().toUpperCase();
              const showSublabel =
                Boolean(normSub) &&
                normSub !== normKind &&
                normSub.replace(/^SHARED\s+/, '') !== normKind &&
                normSub !== normLabel &&
                !REDUNDANT_SUBLABELS.has(normSub);

              const isSelected = selectedNodeId === node.id;
              let borderClass = 'border-[#383838]';
              let bgClass = 'bg-[#141414]';
              let tagColor = 'text-[#8c8c8c]';

              if (node.type === 'domainA') {
                borderClass = isSelected ? 'border-[#f60a00] ring-1 ring-[#f60a00]' : 'border-[#c30800]';
                bgClass = 'bg-[#1a1414]';
                tagColor = 'text-[#c30800]';
              } else if (node.type === 'domainB') {
                borderClass = isSelected ? 'border-[#f600bb] ring-1 ring-[#f600bb]' : 'border-[#c300bb]';
                bgClass = 'bg-[#181418]';
                tagColor = 'text-[#c300bb]';
              } else if (node.type === 'shared') {
                borderClass = isSelected ? 'border-[#bbc300] ring-1 ring-[#bbc300]' : 'border-[#c36a00]';
                bgClass = 'bg-[#181612]';
                tagColor = 'text-[#bbc300]';
              } else if (node.type === 'uniqueA') {
                borderClass = isSelected ? 'border-[#c30800] ring-1 ring-[#c30800]' : 'border-[#c30800]/50';
                tagColor = 'text-[#c30800]';
              } else if (node.type === 'uniqueB') {
                borderClass = isSelected ? 'border-[#c300bb] ring-1 ring-[#c300bb]' : 'border-[#c300bb]/50';
                tagColor = 'text-[#c300bb]';
              }

              return (
                <div
                  key={node.id}
                  onClick={(e) => handleNodeClick(e, node)}
                  style={{
                    position: 'absolute',
                    left: `${node.x}px`,
                    top: `${node.y}px`,
                    width: `${NODE_WIDTH}px`,
                    height: `${NODE_HEIGHT}px`,
                  }}
                  className={`p-2 border ${borderClass} ${bgClass} cursor-pointer transition-colors hover:border-[#f0f0f0]/60 z-10 flex flex-col justify-center`}
                >
                  <div className="flex items-center justify-between gap-1 mb-0.5">
                    <span className={`text-[9px] font-mono uppercase tracking-wider font-bold truncate ${tagColor}`}>
                      {kindLabel}
                    </span>
                  </div>

                  <div className="font-mono text-xs font-bold text-[#f0f0f0] truncate" title={node.label}>
                    {node.label}
                  </div>

                  {showSublabel && (
                    <div className="text-[10px] font-mono text-[#8c8c8c] truncate mt-0.5" title={node.sublabel}>
                      {node.sublabel}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

        {/* Contained Node Details Popup */}
        {selectedNode && popupDetails && popupLayout && (
          <div
            ref={popupRef}
            role="dialog"
            aria-label={`${popupDetails.title} details`}
            onPointerDown={(e) => e.stopPropagation()}
            onClick={(e) => e.stopPropagation()}
            onDoubleClick={(e) => e.stopPropagation()}
            style={{
              position: 'absolute',
              left: `${popupLayout.left}px`,
              top: `${popupLayout.top}px`,
              width: `${popupLayout.width}px`,
              maxHeight: `${popupLayout.maxHeight}px`,
            }}
            className={`z-20 bg-[#141414]/95 backdrop-blur-xs border ${popupBorderAccent} shadow-2xl flex flex-col rounded-none select-text cursor-auto`}
          >
            <div className="px-3 py-2 bg-[#1a1a1a] border-b border-[#2e2e2e] flex items-start justify-between gap-2 shrink-0">
              <div className="min-w-0">
                <div className={`text-[9px] font-mono uppercase tracking-wider font-bold truncate ${popupBadgeAccent}`}>
                  {popupDetails.badge}
                </div>
                <div className="font-mono text-xs font-bold text-[#f0f0f0] break-all mt-0.5">
                  {popupDetails.title}
                </div>
              {popupDetails.subtitle && (
                  <div className="font-mono text-[10px] text-[#8c8c8c] break-words mt-0.5">
                    {popupDetails.subtitle}
                  </div>
                )}
              </div>
            </div>

            <div className="p-3 overflow-y-auto custom-scrollbar space-y-2 text-[11px] font-mono">
              {popupDetails.rows.length > 0 ? (
                popupDetails.rows.map((row, idx) => (
                  <div
                    key={`${row.label}-${idx}`}
                    className="border-b border-[#2e2e2e]/70 pb-1.5 last:border-b-0 last:pb-0"
                  >
                    <div className="text-[9px] uppercase tracking-wider font-bold text-[#8c8c8c]">
                      {row.label}
                    </div>
                    <div className="text-[11px] text-[#f0f0f0] whitespace-pre-line break-words leading-relaxed mt-0.5">
                      {row.value}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-[11px] text-[#8c8c8c]">No additional metadata available for this node.</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
