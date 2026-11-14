// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useMemo } from 'react';
import { WhoisDiffResult } from '../types';
import {
  Search,
  Copy,
  Check,
  Table as TableIcon,
  Columns,
} from 'lucide-react';

interface OsintSubdomainIntersectionProps {
  diff: WhoisDiffResult;
}

type ArchetypeCategory = 'all' | 'auth' | 'api' | 'infra' | 'web' | 'storage';
type LayoutMode = 'tri_panel' | 'table';

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

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedArchetype, setSelectedArchetype] = useState<ArchetypeCategory>('all');
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('tri_panel');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (items: string[], key: string) => {
    try {
      navigator.clipboard.writeText(items.join('\n'));
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {}
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
    const subsB = domainB.crtSubdomainsSample || [];

    const mapA = new Map<string, string>(); // prefix -> full subdomain
    subsA.forEach((s) => {
      const p = getSubdomainPrefix(s, domainA.rootDomain);
      if (p !== '@') mapA.set(p, s);
    });

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
  }, [domainA, domainB]);

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

  // Unified list for Table mode
  const unifiedTableRows = useMemo(() => {
    const rows: Array<{
      id: string;
      host: string;
      domainKey: 'A' | 'B' | 'SHARED';
      domainLabel: string;
      prefix: string;
      category: Exclude<ArchetypeCategory, 'all'>;
      isShared: boolean;
    }> = [];

    filteredShared.forEach((item, idx) => {
      rows.push({
        id: `shared_${idx}`,
        host: `${item.prefix}.* (${item.fullA} / ${item.fullB})`,
        domainKey: 'SHARED',
        domainLabel: 'Shared Archetype',
        prefix: item.prefix,
        category: item.category,
        isShared: true,
      });
    });

    filteredUniqueA.forEach((item, idx) => {
      rows.push({
        id: `uniqA_${idx}`,
        host: item.full,
        domainKey: 'A',
        domainLabel: domainA.domainName,
        prefix: item.prefix,
        category: item.category,
        isShared: false,
      });
    });

    filteredUniqueB.forEach((item, idx) => {
      rows.push({
        id: `uniqB_${idx}`,
        host: item.full,
        domainKey: 'B',
        domainLabel: domainB.domainName,
        prefix: item.prefix,
        category: item.category,
        isShared: false,
      });
    });

    return rows.sort((a, b) => a.prefix.localeCompare(b.prefix));
  }, [filteredShared, filteredUniqueA, filteredUniqueB, domainA.domainName, domainB.domainName]);

  const totalFilteredCount = filteredShared.length + filteredUniqueA.length + filteredUniqueB.length;

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

        <span className="text-[10px] font-mono text-[#737373]">
          {totalFilteredCount} HOSTS
        </span>
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
            placeholder="Filter subdomains..."
            className="w-full pl-8 pr-3 py-1 bg-[#141414] border border-[#2e2e2e] hover:border-[#383838] rounded-none text-xs text-[#f0f0f0] placeholder-[#737373] focus:outline-none focus:border-[#c30800]/60 font-mono transition-colors"
          />
        </div>

        <div className="flex items-center gap-1 font-mono">
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
            onClick={() => setLayoutMode('table')}
            className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer font-semibold ${
              layoutMode === 'table'
                ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                : 'bg-[#141414] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0]'
            }`}
          >
            <TableIcon className="w-3 h-3 text-[#c30800]" />
            <span>Table</span>
          </button>
        </div>
      </div>

      {/* Main Content Area: Tri-Panel or Table Mode */}
      {layoutMode === 'tri_panel' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x divide-[#383838] bg-[#0d0d0d]">
          {/* Panel 1: Unique to Domain A */}
          <div className="flex flex-col">
            <div className="px-3 py-2 bg-[#141414] border-b border-[#2e2e2e] flex items-center justify-between text-xs font-mono border-t-2 border-t-[#c30800]">
              <div className="min-w-0 pr-2">
                <span className="text-[#c30800] font-bold block truncate" title={domainA.domainName}>
                  {domainA.domainName}
                </span>
                <span className="text-[10px] text-[#737373]">
                  {filteredUniqueA.length} unique
                </span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(filteredUniqueA.map((i) => i.full), 'uniqA')}
                className="px-2 py-0.5 text-[10px] font-mono border border-[#383838] bg-[#141414] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer flex items-center gap-1 shrink-0"
              >
                {copiedKey === 'uniqA' ? <Check className="w-2.5 h-2.5 text-[#bbc300]" /> : <Copy className="w-2.5 h-2.5" />}
                <span>{copiedKey === 'uniqA' ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>

            <div className="overflow-y-auto max-h-[480px] custom-scrollbar divide-y divide-[#2e2e2e]/50">
              {filteredUniqueA.length === 0 ? (
                <div className="py-8 text-center text-[#737373] font-mono text-xs">
                  No unique subdomains matching active filter.
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
          <div className="flex flex-col">
            <div className="px-3 py-2 bg-[#141414] border-b border-[#2e2e2e] flex items-center justify-between text-xs font-mono border-t-2 border-t-[#bbc300]">
              <div className="min-w-0 pr-2">
                <span className="text-[#bbc300] font-bold block truncate">
                  SHARED ARCHETYPES
                </span>
                <span className="text-[10px] text-[#737373]">
                  {filteredShared.length} shared
                </span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(filteredShared.map((i) => `${i.prefix} (A: ${i.fullA} | B: ${i.fullB})`), 'shared')}
                className="px-2 py-0.5 text-[10px] font-mono border border-[#383838] bg-[#141414] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer flex items-center gap-1 shrink-0"
              >
                {copiedKey === 'shared' ? <Check className="w-2.5 h-2.5 text-[#bbc300]" /> : <Copy className="w-2.5 h-2.5" />}
                <span>{copiedKey === 'shared' ? 'COPIED' : 'COPY'}</span>
              </button>
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

          {/* Panel 3: Unique to Domain B */}
          <div className="flex flex-col">
            <div className="px-3 py-2 bg-[#141414] border-b border-[#2e2e2e] flex items-center justify-between text-xs font-mono border-t-2 border-t-[#c300bb]">
              <div className="min-w-0 pr-2">
                <span className="text-[#c300bb] font-bold block truncate" title={domainB.domainName}>
                  {domainB.domainName}
                </span>
                <span className="text-[10px] text-[#737373]">
                  {filteredUniqueB.length} unique
                </span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(filteredUniqueB.map((i) => i.full), 'uniqB')}
                className="px-2 py-0.5 text-[10px] font-mono border border-[#383838] bg-[#141414] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer flex items-center gap-1 shrink-0"
              >
                {copiedKey === 'uniqB' ? <Check className="w-2.5 h-2.5 text-[#bbc300]" /> : <Copy className="w-2.5 h-2.5" />}
                <span>{copiedKey === 'uniqB' ? 'COPIED' : 'COPY'}</span>
              </button>
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
        </div>
      ) : (
        /* Unified Table Mode matching DirectoryTableView.tsx */
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="bg-[#1a1a1a] border-b border-[#383838] text-[10px] text-[#8c8c8c] uppercase tracking-wider select-none">
                <th className="py-2.5 px-4 font-semibold w-28">Source</th>
                <th className="py-2.5 px-4 font-semibold">Subdomain / Certificate Subject</th>
                <th className="py-2.5 px-4 font-semibold w-40">Prefix</th>
                <th className="py-2.5 px-4 font-semibold w-36">Archetype</th>
                <th className="py-2.5 px-4 font-semibold w-32">Status</th>
                <th className="py-2.5 px-3 text-right font-semibold w-20">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2e2e2e]">
              {unifiedTableRows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#737373] font-mono text-xs">
                    No Certificate Transparency hosts match search criteria.
                  </td>
                </tr>
              ) : (
                unifiedTableRows.map((row) => {
                  const isCopied = copiedKey === row.id;
                  return (
                    <tr key={row.id} className="hover:bg-[#1a1a1a]/80 transition-colors group cursor-pointer">
                      <td className="py-2.5 px-4 align-middle">
                        <span className="flex items-center font-bold">
                          <span
                            className={
                              row.domainKey === 'A'
                                ? 'text-[#c30800]'
                                : row.domainKey === 'B'
                                ? 'text-[#c300bb]'
                                : 'text-[#bbc300]'
                            }
                          >
                            {row.domainKey}
                          </span>
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-[#f0f0f0] select-all font-mono font-medium truncate max-w-md">
                        {row.host}
                      </td>
                      <td className="py-2.5 px-4 text-[#8c8c8c] font-mono">
                        {row.prefix}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="text-[10px] font-mono text-[#737373] uppercase">
                          {row.category}
                        </span>
                      </td>
                      <td className="py-2.5 px-4">
                        {row.isShared ? (
                          <span className="text-xs font-mono font-bold text-[#bbc300]">
                            SHARED
                          </span>
                        ) : (
                          <span className="text-xs font-mono text-[#737373]">
                            EXCLUSIVE
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right align-middle">
                        <button
                          type="button"
                          onClick={() => handleCopy([row.host], row.id)}
                          className="px-2 py-0.5 text-[10px] font-mono border border-[#383838] bg-[#141414] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer inline-flex items-center gap-1"
                        >
                          {isCopied ? <Check className="w-2.5 h-2.5 text-[#bbc300]" /> : <Copy className="w-2.5 h-2.5" />}
                          <span>{isCopied ? 'COPIED' : 'COPY'}</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
