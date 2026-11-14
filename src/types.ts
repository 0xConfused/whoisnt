// SPDX-License-Identifier: AGPL-3.0-or-later

export interface VerificationTokenItem {
  provider: string;
  token: string;
  raw: string;
}

export interface WhoisDomainRecord {
  queryInput: string;
  domainName: string;
  rootDomain: string;
  tld: string;
  fetchedAt: number;
  source: 'rdap' | 'whois' | 'doh';

  // Registrar & Authority
  registrar: string;
  ianaId?: string;
  whoisServer?: string;
  registrarUrl?: string;
  abuseContactEmail?: string;
  abuseContactPhone?: string;

  // Lifecycle & Dates
  createdDate?: string;
  updatedDate?: string;
  expiresDate?: string;
  domainAgeYears?: number;
  domainAgeFormatted?: string;
  daysUntilExpiration?: number;
  expirationStatus?: 'active' | 'expiring-soon' | 'expired' | 'unknown';
  isSignificantAgeDiscrepancy?: boolean;
  isSignificantExpirationDiscrepancy?: boolean;

  // Security & EPP status flags
  status: string[];
  dnssec: 'signed' | 'unsigned' | 'delegated' | 'unknown';

  // Nameservers & Infrastructure
  nameservers: string[];
  nameserverRoots?: string[];
  dnsProvider?: string;
  aRecords?: string[];
  aaaaRecords?: string[];
  mxRecords?: string[];
  mailProvider?: string;
  soaRecord?: string;
  soaMname?: string;
  soaRname?: string;
  soaSerial?: string;
  ptrRecords?: string[];
  ptrHostnames?: string[];

  // Registrant / Contacts
  registrantOrg?: string;
  registrantCountry?: string;
  registrantState?: string;
  registrantCity?: string;
  isPrivacyProtected?: boolean;

  // OSINT: BGP & Autonomous System Network
  asn?: string;
  asnName?: string;
  bgpPrefix?: string;
  subnet24?: string;

  // OSINT: Live TLS Handshake Inspection
  tlsSubjectCn?: string;
  tlsSubjectOrg?: string;
  tlsIssuerOrg?: string;
  tlsIssuerCn?: string;
  tlsProtocol?: string;
  tlsCipher?: string;
  tlsFingerprint256?: string;
  tlsSans?: string[];

  // OSINT: Certificate Transparency (crt.name / crt.sh)
  crtSubdomainsCount?: number;
  crtSubdomainsSample?: string[];
  crtWildcardFound?: boolean;

  // OSINT: Attribution & Verification Fingerprints
  verificationTokens?: VerificationTokenItem[];
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

  // OSINT: Web Infrastructure
  httpWebServer?: string;
  httpStatusCode?: number;
  hstsEnabled?: boolean;
  cspPresent?: boolean;

  // Raw & Metadata
  rawText: string;
  error?: string;
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
  | 'identity';

export interface FieldDiffItem {
  id: string;
  category: OsintCategory;
  label: string;
  rfcOrSpec?: string;
  valueA: string | string[] | null | undefined;
  valueB: string | string[] | null | undefined;
  status: DiffStatus;
  deltaSummary?: string;
  impactLevel: 'high' | 'medium' | 'low';
  isLowImpact?: boolean;
  isAttributionPivot?: boolean;
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
  highImpactCount: number;
  lowImpactCount: number;
  ageDeltaFormatted?: string;
  expirationDeltaFormatted?: string;
  hasSignificantAgeDiscrepancy: boolean;
  hasSignificantExpirationDiscrepancy: boolean;
  sharedNameserversCount: number;
  totalNameserversCount: number;
  sharedEppCount: number;
  sameRegistrar: boolean;
  sameDnsProvider: boolean;
  sameMailProvider: boolean;
  sameAsn: boolean;
  sameSubnet24: boolean;
  sameTlsSubjectOrg: boolean;
  sharedVerificationTokensCount: number;
  sharedCtSubdomains: string[];
  sameSoaRname?: boolean;
  sameSoaMname?: boolean;
  sharedPtrHostnames?: string[];
  sharedSpfIps?: string[];
  sameDmarcRua?: boolean;
  sameDmarcRuf?: boolean;
  sharedDkimTargets?: string[];
  createdDeltaSeconds?: number;
  updatedDeltaSeconds?: number;
  isCreationClustered?: boolean;
  isUpdateClustered?: boolean;
  linkages: SharedLinkageInsight[];
  overallAttributionVerdict: 'CONFIRMED_SHARED_OWNERSHIP' | 'LIKELY_AFFILIATED' | 'SHARED_CLOUD_INFRASTRUCTURE' | 'DISTINCT_INDEPENDENT_ENTITIES';
}

export interface WhoisDiffResult {
  domainA: WhoisDomainRecord;
  domainB: WhoisDomainRecord;
  fieldDiffs: FieldDiffItem[];
  summary: WhoisDiffSummary;
  rawTextDiff: TextDiffLine[];
  computedAt: number;
}
