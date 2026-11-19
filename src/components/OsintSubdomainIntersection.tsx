// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useMemo } from 'react';
import { WhoisDiffResult, CtCertificateEntry } from '../types';
import {
  Search,
  Columns,
  ShieldCheck,
  ChevronsDownUp,
  ChevronsUpDown,
} from 'lucide-react';
import { CustomSpinner } from './CustomSpinner';

interface OsintSubdomainIntersectionProps {
  diff: WhoisDiffResult;
}

type ArchetypeCategory = 'all' | 'auth' | 'api' | 'infra' | 'web' | 'storage';
type LayoutMode = 'tri_panel' | 'by_cert';
type CertExpiryBucket = 'ACTIVE' | 'EXPIRED' | 'REVOKED';

const ARCHETYPE_PATTERNS: Record<
  Exclude<ArchetypeCategory, 'all'>,
  { label: string; keywords: string[] }
> = {
  auth: { label: 'Auth / Identity', keywords: ['auth', 'sso', 'login', 'oauth', 'saml', 'identity', 'idp', 'signin', 'accounts'] },
  api: { label: 'API / Gateway', keywords: ['api', 'graphql', 'gateway', 'rest', 'rpc', 'v1', 'v2', 'ws', 'endpoints'] },
  infra: { label: 'Infra & Ops', keywords: ['vpn', 'status', 'k8s', 'internal', 'staging', 'dev', 'test', 'bastion', 'monitor', 'grafana', 'ci', 'corp'] },
  web: { label: 'Web & Docs', keywords: ['docs', 'blog', 'pages', 'portal', 'www', 'app', 'community', 'support', 'help'] },
  storage: { label: 'Storage & CDN', keywords: ['cdn', 'assets', 'static', 'media', 's3', 'img', 'upload', 'files'] },
};

export const OsintSubdomainIntersection: React.FC<OsintSubdomainIntersectionProps> = ({ diff }) => {
  const { domainA, domainB } = diff;
  const isSingle = Boolean(diff.isSingleDomain || !domainB);

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedArchetype, setSelectedArchetype] = useState<ArchetypeCategory>('all');
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('tri_panel');
  const [collapsedMap, setCollapsedMap] = useState<Record<string, boolean>>({});

  const toggleCollapsed = (key: string) => {
    setCollapsedMap((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  const getSubdomainPrefix = (sub: string, root: string) => {
    const cleanSub = sub.toLowerCase().replace(/^\*\./, '').trim();
    const cleanRoot = root.toLowerCase().trim();
    if (cleanSub === cleanRoot) return '@';
    if (cleanSub.endsWith(`.${cleanRoot}`)) {
      return cleanSub.slice(0, -(cleanRoot.length + 1));
    }
    return cleanSub.split('.')[0] || cleanSub;
  };

  const classifySubdomain = (prefix: string): Exclude<ArchetypeCategory, 'all'> => {
    const lower = prefix.toLowerCase();
    for (const [cat, conf] of Object.entries(ARCHETYPE_PATTERNS)) {
      if (conf.keywords.some((k) => lower.includes(k))) {
        return cat as Exclude<ArchetypeCategory, 'all'>;
      }
    }
    return 'web';
  };

  const { uniqueA, sharedArchetypes, uniqueB } = useMemo(() => {
    const subsA = domainA.crtSubdomainsSample || [];
    const mapA = new Map<string, string>(); // prefix -> full subdomain
    subsA.forEach((s) => {
      const p = getSubdomainPrefix(s, domainA.rootDomain);
      if (p !== '@') mapA.set(p, s);
    });

    if (!domainB || isSingle) {
      const onlyA: Array<{ prefix: string; full: string; category: Exclude<ArchetypeCategory, 'all'> }> = [];
      mapA.forEach((full, prefix) => {
        onlyA.push({
          prefix,
          full,
          category: classifySubdomain(prefix),
        });
      });
      return {
        uniqueA: onlyA,
        sharedArchetypes: [],
        uniqueB: [],
      };
    }

    const subsB = domainB.crtSubdomainsSample || [];
    const mapB = new Map<string, string>(); // prefix -> full subdomain
    subsB.forEach((s) => {
      const p = getSubdomainPrefix(s, domainB.rootDomain);
      if (p !== '@') mapB.set(p, s);
    });

    const sharedKeys: Array<{
      prefix: string;
      fullA: string;
      fullB: string;
      category: Exclude<ArchetypeCategory, 'all'>;
    }> = [];

    const uniqueListA: Array<{ prefix: string; full: string; category: Exclude<ArchetypeCategory, 'all'> }> = [];
    const uniqueListB: Array<{ prefix: string; full: string; category: Exclude<ArchetypeCategory, 'all'> }> = [];

    mapA.forEach((fullA, prefix) => {
      if (mapB.has(prefix)) {
        sharedKeys.push({
          prefix,
          fullA,
          fullB: mapB.get(prefix)!,
          category: classifySubdomain(prefix),
        });
      } else {
        uniqueListA.push({
          prefix,
          full: fullA,
          category: classifySubdomain(prefix),
        });
      }
    });

    mapB.forEach((fullB, prefix) => {
      if (!mapA.has(prefix)) {
        uniqueListB.push({
          prefix,
          full: fullB,
          category: classifySubdomain(prefix),
        });
      }
    });

    return {
      uniqueA: uniqueListA,
      sharedArchetypes: sharedKeys,
      uniqueB: uniqueListB,
    };
  }, [domainA, domainB, isSingle]);

  // Apply filters
  const filterList = <T extends { prefix: string; category: string }>(items: T[]): T[] => {
    return items.filter((item) => {
      if (selectedArchetype !== 'all' && item.category !== selectedArchetype) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        return item.prefix.toLowerCase().includes(q);
      }
      return true;
    });
  };

  const filteredShared = useMemo(() => filterList(sharedArchetypes), [sharedArchetypes, selectedArchetype, searchQuery]);
  const filteredUniqueA = useMemo(() => filterList(uniqueA), [uniqueA, selectedArchetype, searchQuery]);
  const filteredUniqueB = useMemo(() => filterList(uniqueB), [uniqueB, selectedArchetype, searchQuery]);

  type EnrichedCert = CtCertificateEntry & {
    provider: string;
    matchedNames: Array<{ host: string; category: Exclude<ArchetypeCategory, 'all'> }>;
    statusLabel: CertExpiryBucket;
    notAfterMs: number;
  };

  interface ProviderCertGroup {
    provider: string;
    totalCerts: number;
    expiryBuckets: Array<{
      bucket: CertExpiryBucket;
      certs: EnrichedCert[];
    }>;
  }

  const groupCertsByProviderAndExpiry = (
    certs: CtCertificateEntry[] | undefined,
    rootDomain: string
  ): { groups: ProviderCertGroup[]; totalCerts: number } => {
    const q = searchQuery.toLowerCase().trim();
    const now = Date.now();
    const providerMap = new Map<string, Record<CertExpiryBucket, EnrichedCert[]>>();
    let totalCerts = 0;

    for (const cert of certs || []) {
      const provider = (cert.issuerOrg || cert.issuerCn || 'Unknown Issuer').trim();
      const metaMatch =
        Boolean(q) &&
        (provider.toLowerCase().includes(q) ||
          (cert.issuerCn || '').toLowerCase().includes(q) ||
          (cert.sha256 || '').toLowerCase().includes(q) ||
          cert.id.toLowerCase().includes(q));

      const matchedNames: Array<{ host: string; category: Exclude<ArchetypeCategory, 'all'> }> = [];
      for (const name of cert.dnsNames) {
        const prefix = getSubdomainPrefix(name, rootDomain);
        const category = classifySubdomain(prefix);
        if (selectedArchetype !== 'all' && category !== selectedArchetype) continue;
        if (q && !metaMatch && !name.toLowerCase().includes(q)) continue;
        matchedNames.push({ host: name, category });
      }

      if (matchedNames.length === 0) continue;

      const parsedNotAfter = cert.notAfter ? Date.parse(cert.notAfter) : NaN;
      const notAfterMs = !isNaN(parsedNotAfter) ? parsedNotAfter : 0;
      const statusLabel: CertExpiryBucket = cert.revoked
        ? 'REVOKED'
        : !isNaN(parsedNotAfter) && parsedNotAfter < now
        ? 'EXPIRED'
        : 'ACTIVE';

      if (!providerMap.has(provider)) {
        providerMap.set(provider, { ACTIVE: [], EXPIRED: [], REVOKED: [] });
      }

      providerMap.get(provider)![statusLabel].push({
        ...cert,
        provider,
        matchedNames,
        statusLabel,
        notAfterMs,
      });
      totalCerts++;
    }

    const bucketOrder: CertExpiryBucket[] = ['ACTIVE', 'EXPIRED', 'REVOKED'];
    const groups: ProviderCertGroup[] = [];

    for (const [provider, buckets] of providerMap.entries()) {
      const expiryBuckets: ProviderCertGroup['expiryBuckets'] = [];
      for (const bucket of bucketOrder) {
        const items = buckets[bucket];
        if (items.length === 0) continue;
        // ACTIVE sorted soonest-to-expire first; EXPIRED/REVOKED sorted most recent expiry first
        items.sort((a, b) =>
          bucket === 'ACTIVE' ? a.notAfterMs - b.notAfterMs : b.notAfterMs - a.notAfterMs
        );
        expiryBuckets.push({ bucket, certs: items });
      }

      const groupCount = expiryBuckets.reduce((acc, b) => acc + b.certs.length, 0);
      if (groupCount > 0) {
        groups.push({
          provider,
          totalCerts: groupCount,
          expiryBuckets,
        });
      }
    }

    groups.sort((a, b) => {
      const aHasActive = a.expiryBuckets.some((eb) => eb.bucket === 'ACTIVE');
      const bHasActive = b.expiryBuckets.some((eb) => eb.bucket === 'ACTIVE');
      if (aHasActive !== bHasActive) return aHasActive ? -1 : 1;
      if (b.totalCerts !== a.totalCerts) return b.totalCerts - a.totalCerts;
      return a.provider.localeCompare(b.provider);
    });

    return { groups, totalCerts };
  };

  const certGroupsA = useMemo(
    () => groupCertsByProviderAndExpiry(domainA.crtCertificates, domainA.rootDomain),
    [domainA.crtCertificates, domainA.rootDomain, selectedArchetype, searchQuery]
  );

  const certGroupsB = useMemo(
    () =>
      !isSingle && domainB
        ? groupCertsByProviderAndExpiry(domainB.crtCertificates, domainB.rootDomain)
        : { groups: [], totalCerts: 0 },
    [domainB, isSingle, selectedArchetype, searchQuery]
  );

  const totalFilteredCount = filteredShared.length + filteredUniqueA.length + filteredUniqueB.length;
  const totalCertsCount = certGroupsA.totalCerts + certGroupsB.totalCerts;

  const { allCertCollapsibleKeys, allProviderKeys } = useMemo(() => {
    const allKeys: string[] = [];
    const providerKeys: string[] = [];
    const cols = [
      { key: 'A', domain: domainA.domainName, groups: certGroupsA.groups },
      ...(!isSingle && domainB
        ? [{ key: 'B', domain: domainB.domainName, groups: certGroupsB.groups }]
        : []),
    ];

    for (const col of cols) {
      for (const providerGroup of col.groups) {
        const provKey = `prov:${col.key}:${col.domain}:${providerGroup.provider}`;
        providerKeys.push(provKey);
        allKeys.push(provKey);
        for (const expiryGroup of providerGroup.expiryBuckets) {
          const bucketKey = `bucket:${col.key}:${col.domain}:${providerGroup.provider}:${expiryGroup.bucket}`;
          allKeys.push(bucketKey);
          expiryGroup.certs.forEach((cert, certIdx) => {
            allKeys.push(
              `cert:${col.key}:${col.domain}:${providerGroup.provider}:${expiryGroup.bucket}:${cert.id}-${certIdx}`
            );
          });
        }
      }
    }

    return { allCertCollapsibleKeys: allKeys, allProviderKeys: providerKeys };
  }, [domainA.domainName, domainB, isSingle, certGroupsA.groups, certGroupsB.groups]);

  const areAllCollapsed =
    allProviderKeys.length > 0 &&
    allProviderKeys.every((key) => Boolean(collapsedMap[key]));

  const handleToggleExpandCollapseAll = () => {
    if (areAllCollapsed) {
      setCollapsedMap({});
      return;
    }
    const next: Record<string, boolean> = {};
    for (const key of allCertCollapsibleKeys) {
      next[key] = true;
    }
    setCollapsedMap(next);
  };

  const isCollectingA =
    domainA.crtShStatus === 'collecting' && (domainA.crtCertificates?.length || 0) === 0;
  const isCollectingB = Boolean(
    !isSingle &&
      domainB?.crtShStatus === 'collecting' &&
      (domainB.crtCertificates?.length || 0) === 0
  );
  const isAnyCollecting = isCollectingA || isCollectingB;

  return (
    <div id="ct-subdomains-view" className="bg-[#141414] border border-[#383838] rounded-none overflow-hidden flex flex-col relative mb-6">
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Minimal Archetype Filter Bar */}
      <div className="px-4 py-2.5 bg-[#141414] flex flex-wrap items-center justify-between gap-2 border-b border-[#2e2e2e]">
        <div className="flex flex-wrap items-center gap-1.5">
          {[
            { id: 'all', label: 'All Hosts' },
            { id: 'auth', label: 'Auth / SSO' },
            { id: 'api', label: 'API / Gateway' },
            { id: 'infra', label: 'Infra / Ops' },
            { id: 'web', label: 'Web / Docs' },
            { id: 'storage', label: 'CDN / Assets' },
          ].map((cat) => (
            <button
              key={cat.id}
              type="button"
              onClick={() => setSelectedArchetype(cat.id as ArchetypeCategory)}
              className={`px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer transition-colors font-semibold shrink-0 ${
                selectedArchetype === cat.id
                  ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                  : 'bg-[#0d0d0d] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0] hover:border-[#383838]'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3">
          {isAnyCollecting && (
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#f0f0f0]">
              <CustomSpinner className="w-3 h-3 text-[#c30800] shrink-0" />
              <span className="truncate max-w-[340px]">
                Collecting certificate data
              </span>
            </div>
          )}
          <span className="text-[10px] font-mono text-[#737373]">
            {layoutMode === 'by_cert' ? `${totalCertsCount} CERTS` : `${totalFilteredCount} HOSTS`}
          </span>
        </div>
      </div>

      {/* Sub-bar: Search Bar & Layout Switcher */}
      <div className="px-4 py-2 bg-[#0d0d0d] border-b border-[#383838] flex flex-wrap items-center justify-between gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="w-3.5 h-3.5 text-[#8c8c8c] absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            maxLength={200}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={layoutMode === 'by_cert' ? 'Filter subdomains, CA, or cert hash' : 'Filter subdomains'}
            className="w-full pl-8 pr-3 py-1 bg-[#141414] border border-[#2e2e2e] hover:border-[#383838] rounded-none text-xs text-[#f0f0f0] placeholder-[#737373] focus:outline-none focus:border-[#c30800]/60 font-mono transition-colors"
          />
        </div>

        <div className="flex items-center gap-1 font-mono">
          {layoutMode === 'by_cert' && allCertCollapsibleKeys.length > 0 && (
            <button
              type="button"
              onClick={handleToggleExpandCollapseAll}
              title={areAllCollapsed ? 'Expand all certificate groups' : 'Collapse all certificate groups'}
              className={`px-2.5 py-1 rounded-none font-mono text-[10px] uppercase tracking-wider border transition-colors cursor-pointer flex items-center justify-center gap-1.5 min-w-[115px] shrink-0 ${
                !areAllCollapsed
                  ? 'bg-[#1a1a1a] border-[#c30800] text-[#f0f0f0] font-semibold'
                  : 'bg-[#141414] hover:bg-[#262626] border-[#383838] text-[#8c8c8c] hover:text-[#f0f0f0]'
              }`}
            >
              {!areAllCollapsed ? (
                <>
                  <ChevronsDownUp className="w-3.5 h-3.5 text-[#c30800]" />
                  <span>Collapse All</span>
                </>
              ) : (
                <>
                  <ChevronsUpDown className="w-3.5 h-3.5 text-[#c30800]" />
                  <span>Expand All</span>
                </>
              )}
            </button>
          )}
          <button
            type="button"
            onClick={() => setLayoutMode('tri_panel')}
            className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer font-semibold ${
              layoutMode === 'tri_panel'
                ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                : 'bg-[#141414] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0]'
            }`}
          >
            <Columns className="w-3 h-3 text-[#c30800]" />
            <span>Panels</span>
          </button>
          <button
            type="button"
            onClick={() => setLayoutMode('by_cert')}
            className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer font-semibold ${
              layoutMode === 'by_cert'
                ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                : 'bg-[#141414] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0]'
            }`}
          >
            <ShieldCheck className="w-3 h-3 text-[#c30800]" />
            <span>By Cert</span>
          </button>
        </div>
      </div>

      {/* Main Content Area: Tri-Panel or By Cert Mode */}
      {layoutMode === 'tri_panel' ? (
        <div
          className={
            isSingle
              ? 'grid grid-cols-1 bg-[#0d0d0d]'
              : 'grid grid-cols-1 lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x divide-[#383838] bg-[#0d0d0d]'
          }
        >
          {/* Panel 1: Domain A */}
          <div className="flex flex-col">
            <div className="px-3 py-2 bg-[#141414] border-b border-[#2e2e2e] flex items-center justify-between text-xs font-mono border-t-2 border-t-[#c30800]">
              <div className="min-w-0">
                <span className="text-[#c30800] font-bold block truncate" title={domainA.domainName}>
                  {domainA.domainName}
                </span>
                <span className="text-[10px] text-[#737373]">
                  {filteredUniqueA.length} {isSingle ? 'observed' : 'unique'}
                </span>
              </div>
            </div>

            <div className="overflow-y-auto max-h-[480px] custom-scrollbar divide-y divide-[#2e2e2e]/50">
              {filteredUniqueA.length === 0 ? (
                <div className="py-8 text-center text-[#737373] font-mono text-xs">
                  {isSingle
                    ? 'No subdomains matching active filter.'
                    : 'No unique subdomains matching active filter.'}
                </div>
              ) : (
                filteredUniqueA.map((item, idx) => (
                  <div
                    key={idx}
                    className="px-3 py-1.5 hover:bg-[#141414] transition-colors flex items-center justify-between gap-2 text-xs font-mono"
                  >
                    <span className="text-[#f0f0f0] truncate select-all">{item.full}</span>
                    <span className="text-[9px] font-mono text-[#737373] shrink-0 uppercase">
                      {item.category}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Panel 2: Shared Archetypes */}
          {!isSingle && domainB && (
            <div className="flex flex-col">
              <div className="px-3 py-2 bg-[#141414] border-b border-[#2e2e2e] flex items-center justify-between text-xs font-mono border-t-2 border-t-[#bbc300]">
                <div className="min-w-0">
                  <span className="text-[#bbc300] font-bold block truncate">
                    SHARED ARCHETYPES
                  </span>
                  <span className="text-[10px] text-[#737373]">
                    {filteredShared.length} shared
                  </span>
                </div>
              </div>

              <div className="overflow-y-auto max-h-[480px] custom-scrollbar divide-y divide-[#2e2e2e]/50">
                {filteredShared.length === 0 ? (
                  <div className="py-8 text-center text-[#737373] font-mono text-xs">
                    No common subdomain naming archetypes identified between targets.
                  </div>
                ) : (
                  filteredShared.map((item, idx) => (
                    <div
                      key={idx}
                      className="px-3 py-2 hover:bg-[#141414] transition-colors flex flex-col gap-0.5 text-xs font-mono"
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-bold text-[#bbc300]">
                          {item.prefix}
                        </span>
                        <span className="text-[9px] font-mono text-[#737373] shrink-0 uppercase">
                          {item.category}
                        </span>
                      </div>
                      <div className="text-[11px] text-[#8c8c8c] flex flex-col gap-0.5 pl-2 border-l border-[#2e2e2e]">
                        <span className="truncate text-[#f0f0f0]">{item.fullA}</span>
                        <span className="truncate text-[#f0f0f0]">{item.fullB}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Panel 3: Unique to Domain B */}
          {!isSingle && domainB && (
            <div className="flex flex-col">
              <div className="px-3 py-2 bg-[#141414] border-b border-[#2e2e2e] flex items-center justify-between text-xs font-mono border-t-2 border-t-[#c300bb]">
                <div className="min-w-0">
                  <span className="text-[#c300bb] font-bold block truncate" title={domainB.domainName}>
                    {domainB.domainName}
                  </span>
                  <span className="text-[10px] text-[#737373]">
                    {filteredUniqueB.length} unique
                  </span>
                </div>
              </div>

              <div className="overflow-y-auto max-h-[480px] custom-scrollbar divide-y divide-[#2e2e2e]/50">
                {filteredUniqueB.length === 0 ? (
                  <div className="py-8 text-center text-[#737373] font-mono text-xs">
                    No unique subdomains matching active filter.
                  </div>
                ) : (
                  filteredUniqueB.map((item, idx) => (
                    <div
                      key={idx}
                      className="px-3 py-1.5 hover:bg-[#141414] transition-colors flex items-center justify-between gap-2 text-xs font-mono"
                    >
                      <span className="text-[#f0f0f0] truncate select-all">{item.full}</span>
                      <span className="text-[9px] font-mono text-[#737373] shrink-0 uppercase">
                        {item.category}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div
          className={
            isSingle
              ? 'grid grid-cols-1 bg-[#0d0d0d]'
              : 'grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-[#383838] bg-[#0d0d0d]'
          }
        >
          {[
            {
              key: 'A',
              domain: domainA.domainName,
              accentText: 'text-[#c30800]',
              accentBorder: 'border-t-[#c30800]',
              groups: certGroupsA.groups,
              totalCerts: certGroupsA.totalCerts,
              crtShStatus: domainA.crtShStatus,
              crtShAttempt: domainA.crtShAttempt,
            },
            ...(!isSingle && domainB
              ? [
                  {
                    key: 'B',
                    domain: domainB.domainName,
                    accentText: 'text-[#c300bb]',
                    accentBorder: 'border-t-[#c300bb]',
                    groups: certGroupsB.groups,
                    totalCerts: certGroupsB.totalCerts,
                    crtShStatus: domainB.crtShStatus,
                    crtShAttempt: domainB.crtShAttempt,
                  },
                ]
              : []),
          ].map((col) => (
            <div key={col.key} className="flex flex-col min-w-0">
              <div
                className={`px-3 py-2 bg-[#141414] border-b border-[#2e2e2e] flex items-center justify-between gap-2 text-xs font-mono border-t-2 ${col.accentBorder}`}
              >
                <div className="min-w-0">
                  <span className={`${col.accentText} font-bold block truncate`} title={col.domain}>
                    {col.domain}
                  </span>
                  <span className="text-[10px] text-[#737373]">
                    {col.groups.length} {col.groups.length === 1 ? 'provider' : 'providers'} · {col.totalCerts}{' '}
                    {col.totalCerts === 1 ? 'certificate' : 'certificates'}
                  </span>
                </div>
                {col.crtShStatus === 'collecting' && (
                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#8c8c8c] shrink-0">
                    <CustomSpinner className="w-3 h-3 text-[#c30800] shrink-0" />
                    <span>
                      COLLECTING CERTS{col.crtShAttempt ? ` (TRY ${col.crtShAttempt})` : ''}
                    </span>
                  </div>
                )}
              </div>

              <div className="p-3 space-y-3">
                {col.groups.length === 0 ? (
                  col.crtShStatus === 'collecting' ? (
                    <div className="py-10 flex items-center justify-center gap-2 text-[#8c8c8c] font-mono text-xs">
                      <CustomSpinner className="w-3.5 h-3.5 text-[#c30800] shrink-0" />
                      <span>
                        Collecting certificate data from crt.sh
                        {col.crtShAttempt ? ` (attempt ${col.crtShAttempt})` : ''}...
                      </span>
                    </div>
                  ) : (
                    <div className="py-10 text-center text-[#737373] font-mono text-xs">
                      No CT certificate issuances matching active filter.
                    </div>
                  )
                ) : (
                  col.groups.map((providerGroup) => {
                    const provKey = `prov:${col.key}:${col.domain}:${providerGroup.provider}`;
                    const isProvCollapsed = Boolean(collapsedMap[provKey]);

                    return (
                      <div
                        key={providerGroup.provider}
                        className="bg-[#141414] border border-[#383838] rounded-none overflow-hidden"
                      >
                        {/* Level 1: Certificate Provider Header */}
                        <div
                          role="button"
                          tabIndex={0}
                          onClick={() => toggleCollapsed(provKey)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              toggleCollapsed(provKey);
                            }
                          }}
                          aria-expanded={!isProvCollapsed}
                          className={`px-3 py-2 bg-[#1a1a1a] hover:bg-[#222222] transition-colors cursor-pointer select-none flex items-center justify-between gap-2 font-mono ${
                            !isProvCollapsed ? 'border-b border-[#383838]' : ''
                          }`}
                        >
                          <div className="flex items-center min-w-0">
                            <span className="text-xs font-bold text-[#f0f0f0] truncate" title={providerGroup.provider}>
                              {providerGroup.provider}
                            </span>
                          </div>
                        </div>

                        {/* Level 2: Expiry Buckets (ACTIVE -> EXPIRED -> REVOKED) */}
                        {!isProvCollapsed && (
                          <div className="divide-y divide-[#383838]">
                            {providerGroup.expiryBuckets.map((expiryGroup) => {
                              const bucketKey = `bucket:${col.key}:${col.domain}:${providerGroup.provider}:${expiryGroup.bucket}`;
                              const isBucketCollapsed = Boolean(collapsedMap[bucketKey]);

                              return (
                                <div key={expiryGroup.bucket} className="bg-[#0d0d0d]">
                                  <div
                                    role="button"
                                    tabIndex={0}
                                    onClick={() => toggleCollapsed(bucketKey)}
                                    onKeyDown={(e) => {
                                      if (e.key === 'Enter' || e.key === ' ') {
                                        e.preventDefault();
                                        toggleCollapsed(bucketKey);
                                      }
                                    }}
                                    aria-expanded={!isBucketCollapsed}
                                    className={`px-3 py-1.5 bg-[#121212] hover:bg-[#1a1a1a] transition-colors cursor-pointer select-none flex items-center justify-between gap-2 font-mono ${
                                      !isBucketCollapsed ? 'border-b border-[#2e2e2e]' : ''
                                    }`}
                                  >
                                    <div className="flex items-center min-w-0">
                                      <span className="text-[10px] font-bold uppercase tracking-wider text-[#f0f0f0]">
                                        {expiryGroup.bucket}
                                      </span>
                                    </div>
                                  </div>

                                  {!isBucketCollapsed && (
                                    <div className="p-2.5 space-y-2">
                                      {expiryGroup.certs.map((cert, certIdx) => {
                                        const nb = cert.notBefore ? cert.notBefore.slice(0, 10) : '?';
                                        const na = cert.notAfter ? cert.notAfter.slice(0, 10) : '?';
                                        const shortHash = cert.sha256 ? cert.sha256.slice(0, 12) : `ID:${cert.id}`;

                                        const certKey = `cert:${col.key}:${col.domain}:${providerGroup.provider}:${expiryGroup.bucket}:${cert.id}-${certIdx}`;
                                        const isCertCollapsed = Boolean(collapsedMap[certKey]);

                                        return (
                                          <div
                                            key={`${cert.id}-${certIdx}`}
                                            className="bg-[#141414] border border-[#2e2e2e] rounded-none overflow-hidden"
                                          >
                                            <div
                                              role="button"
                                              tabIndex={0}
                                              onClick={() => toggleCollapsed(certKey)}
                                              onKeyDown={(e) => {
                                                if (e.key === 'Enter' || e.key === ' ') {
                                                  e.preventDefault();
                                                  toggleCollapsed(certKey);
                                                }
                                              }}
                                              aria-expanded={!isCertCollapsed}
                                              className={`px-2.5 py-1.5 bg-[#181818] hover:bg-[#202020] transition-colors cursor-pointer select-none flex items-center justify-between gap-2 font-mono ${
                                                !isCertCollapsed ? 'border-b border-[#2e2e2e]' : ''
                                              }`}
                                            >
                                              <div className="flex items-center min-w-0">
                                                <div className="min-w-0">
                                                  <div className="text-[11px] font-semibold text-[#f0f0f0] flex flex-wrap items-center gap-x-2 gap-y-0.5">
                                                    <span>EXP {na}</span>
                                                    <span className="text-[10px] text-[#737373]">ISSUED {nb}</span>
                                                    {cert.issuerCn && cert.issuerCn !== providerGroup.provider && (
                                                      <span className="text-[10px] text-[#8c8c8c] truncate max-w-[180px]" title={cert.issuerCn}>
                                                        {cert.issuerCn}
                                                      </span>
                                                    )}
                                                    <span className="text-[10px] text-[#737373]" title={cert.sha256 || cert.id}>
                                                      {shortHash}
                                                    </span>
                                                  </div>
                                                </div>
                                              </div>
                                            </div>

                                            {!isCertCollapsed && (
                                              <div className="divide-y divide-[#2e2e2e]/50 bg-[#0d0d0d]">
                                                {cert.matchedNames.map((entry, idx) => (
                                                  <div
                                                    key={`${entry.host}-${idx}`}
                                                    className="px-2.5 py-1 hover:bg-[#141414] transition-colors flex items-center justify-between gap-2 text-xs font-mono"
                                                  >
                                                    <span className="text-[#f0f0f0] truncate select-all">
                                                      {entry.host}
                                                    </span>
                                                    <span className="text-[9px] font-mono text-[#737373] shrink-0 uppercase">
                                                      {entry.host.startsWith('*.') ? 'WILDCARD // ' : ''}
                                                      {entry.category}
                                                    </span>
                                                  </div>
                                                ))}
                                              </div>
                                            )}
                                          </div>
                                        );
                                      })}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
