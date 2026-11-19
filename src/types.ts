// SPDX-License-Identifier: AGPL-3.0-or-later

export interface VerificationTokenItem {
  provider: string;
  token: string;
  raw: string;
}

export interface CtCertificateEntry {
  id: string;
  issuerOrg?: string;
  issuerCn?: string;
  notBefore?: string;
  notAfter?: string;
  revoked?: boolean;
  sha256?: string;
  dnsNames: string[];
}

export interface WhoisDomainRecord {
  domainName: string;
  rootDomain: string;
  source: 'rdap' | 'whois' | 'doh';

  // Registrar & Authority
  registrar: string;
  abuseContactEmail?: string;

  // Lifecycle & Dates
  createdDate?: string;
  updatedDate?: string;
  expiresDate?: string;
  domainAgeYears?: number;
  domainAgeFormatted?: string;
  daysUntilExpiration?: number;
  expirationStatus?: 'active' | 'expiring-soon' | 'expired' | 'unknown';

  // Security & EPP status flags
  status: string[];
  dnssec: 'signed' | 'unsigned';

  // Nameservers & Infrastructure
  nameservers: string[];
  dnsProvider?: string;
  aRecords?: string[];
  aaaaRecords?: string[];
  mailProvider?: string;
  soaMname?: string;
  soaRname?: string;
  soaSerial?: string;
  ptrRecords?: string[];
  ptrHostnames?: string[];

  // Registrant / Contacts
  registrantOrg?: string;
  registrantCountry?: string;
  registrantState?: string;

  // OSINT: BGP & Autonomous System Network
  asn?: string;
  asnName?: string;
  subnet24?: string;

  // OSINT: Passive DNS (Historical Resolutions)
  passiveDnsDisplay?: string[];
  passiveDnsIps?: string[];
  pdnsQueriedSubdomainsCount?: number;

  // OSINT: Live TLS Handshake & Certificate Inspection
  tlsSubjectCn?: string;
  tlsSubjectOrg?: string;
  tlsIssuerOrg?: string;
  tlsIssuerCn?: string;
  tlsProtocol?: string;
  tlsCipher?: string;
  tlsValidityNotBefore?: string;
  tlsValidityNotAfter?: string;

  // OSINT: Certificate Transparency (crt.name / Certspotter / crt.sh)
  crtSubdomainsCount?: number;
  crtSubdomainsSample?: string[];
  crtWildcardFound?: boolean;
  crtCertificates?: CtCertificateEntry[];
  crtShStatus?: 'idle' | 'collecting' | 'complete';
  crtShAttempt?: number;

  // OSINT: Attribution & Verification Fingerprints
  verificationTokens?: VerificationTokenItem[];
  htmlVerificationTokens?: VerificationTokenItem[];
  analyticsIds?: string[];
  footerCopyrights?: string[];
  copyrightEntities?: string[];
  spfRecord?: string;
  spfIncludes?: string[];
  spfIpMechanisms?: string[];
  dmarcPolicy?: string;
  dmarcRua?: string;
  dmarcRuf?: string;
  dkimSelectors?: string[];
  dkimCnames?: string[];
  caaRecords?: string[];
  caaIodef?: string[];
  dsRecords?: string[];
  dnskeyRecords?: string[];

  // OSINT: Web Infrastructure, Headers, DOM, Resources & Tech Stack (Static/Inert Analysis Only)
  httpWebServer?: string;
  httpStatusCode?: number;
  httpHeaderSummary?: string[];
  cspExternalDomains?: string[];
  webReconMode?: 'server-direct' | 'browser-cors' | 'cors-blocked' | 'unreachable';
  webFinalUrl?: string;
  inspectedScriptsCount?: number;
  webReconProbedHostsCount?: number;
  webReconReachableHosts?: string[];

  // HTML Metadata & DOM Inspection
  htmlTitle?: string;
  htmlDescription?: string;
  htmlGenerator?: string;
  htmlAuthor?: string;
  htmlRobots?: string;
  canonicalUrl?: string;
  openGraphSiteName?: string;
  twitterSite?: string;
  domMarkers?: string[];
  domStats?: string;

  // Script URLs, Resource Enumeration, Technologies & External Domains
  scriptUrls?: string[];
  resourceSummary?: string[];
  technologies?: string[];
  externalDomains?: string[];

  // Raw Buffer
  rawText: string;
}

export type DiffStatus = 'MATCH' | 'DIFF' | 'ONLY_A' | 'ONLY_B';

export type OsintCategory =
  | 'attribution'
  | 'network'
  | 'certificates'
  | 'infrastructure'
  | 'registrar'
  | 'security'
  | 'lifecycle'
  | 'web';

export interface FieldDiffItem {
  id: string;
  category: OsintCategory;
  label: string;
  rfcOrSpec?: string;
  valueA: string | string[] | null | undefined;
  valueB: string | string[] | null | undefined;
  status: DiffStatus;
  deltaSummary?: string;
  isLowImpact?: boolean;
}

export interface TextDiffLine {
  type: 'add' | 'delete' | 'same' | 'header';
  text: string;
  lineA?: number;
  lineB?: number;
}

export interface SharedLinkageInsight {
  type: 'attribution' | 'network' | 'infrastructure' | 'certificates' | 'registrar';
  title: string;
  description: string;
  strength: 'definitive' | 'strong' | 'moderate' | 'weak';
}

export interface WhoisDiffSummary {
  totalFieldsCompared: number;
  divergentCount: number;
  matchingCount: number;
  ageDeltaFormatted?: string;
  expirationDeltaFormatted?: string;
  sharedNameserversCount: number;
  totalNameserversCount: number;
  sameRegistrar: boolean;
  sameDnsProvider: boolean;
  sameMailProvider: boolean;
  sameAsn: boolean;
  sameSubnet24: boolean;
  sameTlsSubjectOrg: boolean;
  sharedVerificationTokensCount: number;
  sharedAnalyticsIds?: string[];
  sharedCopyrightEntities?: string[];
  sharedExternalDomains?: string[];
  sharedPassiveDnsIps?: string[];
  sameSoaRname?: boolean;
  sharedPtrHostnames?: string[];
  sharedSpfIps?: string[];
  sameDmarcRua?: boolean;
  sameDmarcRuf?: boolean;
  sharedDkimTargets?: string[];
  linkages: SharedLinkageInsight[];
  overallAttributionVerdict: 'CONFIRMED_SHARED_OWNERSHIP' | 'LIKELY_AFFILIATED' | 'SHARED_CLOUD_INFRASTRUCTURE' | 'DISTINCT_INDEPENDENT_ENTITIES';
}

export interface WhoisDiffResult {
  isSingleDomain?: boolean;
  domainA: WhoisDomainRecord;
  domainB?: WhoisDomainRecord;
  fieldDiffs: FieldDiffItem[];
  summary: WhoisDiffSummary;
  rawTextDiff: TextDiffLine[];
  computedAt: number;
}
