// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { WhoisDiffResult, FieldDiffItem } from '../types';
import {
  Search,
  Code2,
  Link2,
  Network,
  Globe,
  Lock,
  Server,
} from 'lucide-react';

interface OsintWebSurfaceViewProps {
  diff: WhoisDiffResult;
}

export const WEB_RECON_FIELD_IDS = new Set<string>([
  'analytics_ids',
  'html_verification_tokens',
  'tls_validity',
  'passive_dns_records',
  'web_recon_status',
  'web_probed_hosts',
  'http_headers',
  'csp_external_domains',
  'html_metadata',
  'dom_inspection',
  'technologies',
  'script_urls',
  'resource_enumeration',
  'external_domains',
]);

type WebScopeFilter =
  | 'all'
  | 'analytics'
  | 'dom_tech'
  | 'external'
  | 'headers'
  | 'metadata'
  | 'pdns_tls'
  | 'resources';

type StatusFilter = 'all' | 'diff_only' | 'match_only';

interface WebSectionMeta {
  key: string;
  label: string;
  scope: Exclude<WebScopeFilter, 'all'>;
  icon: React.FC<{ className?: string }>;
}

const FIELD_SECTION_MAP: Record<string, WebSectionMeta> = {
  analytics_ids: { key: 'analytics', label: 'ANALYTICS & TRACKING', scope: 'analytics', icon: Link2 },
  html_verification_tokens: { key: 'metadata', label: 'HTML METADATA & VERIFICATION', scope: 'metadata', icon: Link2 },
  html_metadata: { key: 'metadata', label: 'HTML METADATA & VERIFICATION', scope: 'metadata', icon: Code2 },
  dom_inspection: { key: 'dom_tech', label: 'DOM & TECHNOLOGY STACK', scope: 'dom_tech', icon: Code2 },
  technologies: { key: 'dom_tech', label: 'DOM & TECHNOLOGY STACK', scope: 'dom_tech', icon: Code2 },
  http_headers: { key: 'headers', label: 'HTTP HEADERS & ACCESS', scope: 'headers', icon: Server },
  web_recon_status: { key: 'headers', label: 'HTTP HEADERS & ACCESS', scope: 'headers', icon: Server },
  web_probed_hosts: { key: 'headers', label: 'HTTP HEADERS & ACCESS', scope: 'headers', icon: Server },
  csp_external_domains: { key: 'external', label: 'EXTERNAL DOMAINS & CSP', scope: 'external', icon: Globe },
  external_domains: { key: 'external', label: 'EXTERNAL DOMAINS & CSP', scope: 'external', icon: Globe },
  passive_dns_records: { key: 'pdns_tls', label: 'PASSIVE DNS & TLS VALIDITY', scope: 'pdns_tls', icon: Network },
  tls_validity: { key: 'pdns_tls', label: 'PASSIVE DNS & TLS VALIDITY', scope: 'pdns_tls', icon: Lock },
  script_urls: { key: 'resources', label: 'SCRIPTS & STATIC RESOURCES', scope: 'resources', icon: Code2 },
  resource_enumeration: { key: 'resources', label: 'SCRIPTS & STATIC RESOURCES', scope: 'resources', icon: Code2 },
};

const isUnavailableText = (raw: unknown): boolean => {
  if (raw === null || raw === undefined) return true;
  const s = String(raw).trim().toLowerCase();
  if (!s) return true;
  return (
    s === 'not available' ||
    s === 'not inspected' ||
    s === 'no tracking ids extracted' ||
    s === 'none detected in <head>' ||
    s === 'no historical pdns records observed' ||
    s === 'headers not exposed / cors restricted' ||
    s === 'none declared in csp' ||
    s === 'no html metadata extracted' ||
    s === 'no dom structure parsed' ||
    s === 'no stack signatures matched' ||
    s === 'no external/linked scripts' ||
    s === 'no static assets enumerated' ||
    s === 'no external domains discovered' ||
    s === 'unreachable over http/https' ||
    s === 'no reachable subdomains observed' ||
    s.startsWith('blocked by target cors policy')
  );
};

const isFieldUnavailable = (val: string | string[] | null | undefined): boolean => {
  if (val === null || val === undefined) return true;
  if (Array.isArray(val)) {
    return val.length === 0 || val.every((item) => isUnavailableText(item));
  }
  return isUnavailableText(val);
};

export const OsintWebSurfaceView: React.FC<OsintWebSurfaceViewProps> = ({ diff }) => {
  const { domainA, domainB, fieldDiffs } = diff;
  const isSingle = Boolean(diff.isSingleDomain || !domainB);

  const [activeScope, setActiveScope] = useState<WebScopeFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [hideUnavailable, setHideUnavailable] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedRowIds, setExpandedRowIds] = useState<Set<string>>(new Set());

  const containerRef = useRef<HTMLDivElement | null>(null);
  const theadRef = useRef<HTMLTableSectionElement | null>(null);

  useEffect(() => {
    const updateTheadHeight = () => {
      if (containerRef.current && theadRef.current) {
        const h = Math.max(0, Math.floor(theadRef.current.getBoundingClientRect().height) - 1);
        containerRef.current.style.setProperty('--matrix-thead-height', `${h}px`);
      }
    };
    updateTheadHeight();
    const observer = new ResizeObserver(updateTheadHeight);
    if (theadRef.current) observer.observe(theadRef.current);
    return () => observer.disconnect();
  }, [domainA.domainName, domainB?.domainName]);

  const toggleRowExpand = useCallback((id: string) => {
    setExpandedRowIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const webFields = useMemo(() => {
    return fieldDiffs.filter(
      (f) => f.category === 'web' || WEB_RECON_FIELD_IDS.has(f.id)
    );
  }, [fieldDiffs]);

  const fieldsBeforeScope = useMemo(() => {
    return webFields.filter((field) => {
      if (!isSingle) {
        if (statusFilter === 'diff_only' && field.status === 'MATCH') return false;
        if (statusFilter === 'match_only' && field.status !== 'MATCH') return false;
      }
      if (hideUnavailable && isFieldUnavailable(field.valueA) && (isSingle || isFieldUnavailable(field.valueB))) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const strA = Array.isArray(field.valueA) ? field.valueA.join(' ') : String(field.valueA || '');
        const strB = !isSingle
          ? Array.isArray(field.valueB)
            ? field.valueB.join(' ')
            : String(field.valueB || '')
          : '';
        return (
          field.label.toLowerCase().includes(q) ||
          (field.rfcOrSpec || '').toLowerCase().includes(q) ||
          strA.toLowerCase().includes(q) ||
          strB.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [webFields, statusFilter, hideUnavailable, searchQuery, isSingle]);

  const filteredFields = useMemo(() => {
    if (activeScope === 'all') return fieldsBeforeScope;
    return fieldsBeforeScope.filter((f) => FIELD_SECTION_MAP[f.id]?.scope === activeScope);
  }, [fieldsBeforeScope, activeScope]);

  // Group into alphabetical sections with alphabetical rows
  const groupedSections = useMemo(() => {
    const map = new Map<string, { meta: WebSectionMeta; fields: FieldDiffItem[] }>();
    for (const field of filteredFields) {
      const meta = FIELD_SECTION_MAP[field.id] || {
        key: 'other',
        label: 'WEB RECONNAISSANCE',
        scope: 'dom_tech' as const,
        icon: Code2,
      };
      if (!map.has(meta.label)) {
        map.set(meta.label, { meta, fields: [] });
      }
      map.get(meta.label)!.fields.push(field);
    }

    return Array.from(map.values())
      .sort((a, b) => a.meta.label.localeCompare(b.meta.label, undefined, { sensitivity: 'base' }))
      .map((entry) => ({
        ...entry,
        fields: [...entry.fields].sort((a, b) =>
          a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' })
        ),
      }));
  }, [filteredFields]);

  const renderArrayValues = (values: string[], isExpanded: boolean) => {
    if (!values || values.length === 0) {
      return <span className="text-[#737373] italic font-mono text-xs">No records observed</span>;
    }

    const sortedValues = [...values].sort((a, b) =>
      String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' })
    );
    const limit = 4;
    const isOverLimit = sortedValues.length > limit;
    const displayedValues = !isExpanded && isOverLimit ? sortedValues.slice(0, limit) : sortedValues;

    return (
      <div className="space-y-1.5 font-mono text-xs">
        {displayedValues.map((val, idx) => (
          <div key={idx} className="flex items-center min-w-0">
            <span className="font-mono text-xs break-all text-[#f0f0f0]">
              {val}
            </span>
          </div>
        ))}
        {isOverLimit && (
          <div className="pt-0.5 text-[10px] font-mono text-[#8c8c8c]">
            {isExpanded
              ? `Showing all ${sortedValues.length} records (click row to minimize)`
              : `+ ${sortedValues.length - limit} more records (click row to expand)`}
          </div>
        )}
      </div>
    );
  };

  const renderSingleValue = (val: unknown, isExpanded: boolean) => {
    const textVal = val !== undefined && val !== null ? String(val) : '';
    const isLong = textVal.length > 180;
    const displayText = isLong && !isExpanded ? `${textVal.slice(0, 160)}...` : textVal;

    return (
      <div className="flex flex-col gap-1">
        <span className={`font-mono text-xs break-all ${textVal ? 'text-[#f0f0f0]' : 'text-[#737373] italic'}`}>
          {displayText || 'Not available'}
        </span>
        {isLong && (
          <div className="text-[10px] font-mono text-[#8c8c8c]">
            {isExpanded ? 'Click row to minimize' : `Click row to expand (${textVal.length} chars)`}
          </div>
        )}
      </div>
    );
  };

  const scopeButtons: Array<{ id: WebScopeFilter; label: string }> = [
    { id: 'all', label: 'All' },
    { id: 'analytics', label: 'Analytics' },
    { id: 'dom_tech', label: 'DOM & Tech' },
    { id: 'external', label: 'External Origins' },
    { id: 'headers', label: 'Headers' },
    { id: 'metadata', label: 'Metadata' },
    { id: 'pdns_tls', label: 'Passive DNS & TLS' },
    { id: 'resources', label: 'Scripts & Assets' },
  ];

  return (
    <div
      ref={containerRef}
      id="web-recon-surface-view"
      className="bg-[#141414] border border-[#383838] rounded-none overflow-x-clip flex flex-col relative z-0 isolate mb-6"
    >
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Scope Filter Bar */}
      <div className="px-4 py-2.5 bg-[#141414] flex flex-wrap items-center gap-1.5 border-b border-[#2e2e2e]">
        {scopeButtons.map((btn) => {
          const count =
            btn.id === 'all'
              ? fieldsBeforeScope.length
              : fieldsBeforeScope.filter((f) => FIELD_SECTION_MAP[f.id]?.scope === btn.id).length;
          return (
            <button
              key={btn.id}
              type="button"
              onClick={() => setActiveScope(btn.id)}
              className={`px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer transition-colors font-semibold shrink-0 ${
                activeScope === btn.id
                  ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                  : 'bg-[#0d0d0d] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0] hover:border-[#383838]'
              }`}
            >
              {btn.label} ({count})
            </button>
          );
        })}
      </div>

      {/* Search & Status Controls */}
      <div className="px-4 py-2 bg-[#0d0d0d] border-b border-[#383838] flex flex-wrap items-center justify-between gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="w-3.5 h-3.5 text-[#8c8c8c] absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            maxLength={200}
            placeholder="Filter headers, scripts, analytics IDs, passive DNS"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1 bg-[#141414] border border-[#2e2e2e] hover:border-[#383838] rounded-none text-xs text-[#f0f0f0] placeholder-[#737373] focus:outline-none focus:border-[#c30800]/60 font-mono transition-colors"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {!isSingle && (
            <div
              role="group"
              aria-label="Web recon diff status filter"
              className="inline-flex items-center bg-[#0d0d0d] border border-[#383838] rounded-none p-0.5 gap-0.5"
            >
              {(
                [
                  { id: 'all', label: 'ALL' },
                  { id: 'diff_only', label: 'DIFFS' },
                  { id: 'match_only', label: 'MATCHES' },
                ] as const
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setStatusFilter(opt.id)}
                  className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded-none border cursor-pointer font-semibold transition-colors ${
                    statusFilter === opt.id
                      ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                      : 'bg-[#141414] text-[#8c8c8c] border-transparent hover:text-[#f0f0f0]'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}

          <button
            type="button"
            onClick={() => setHideUnavailable((prev) => !prev)}
            aria-pressed={hideUnavailable}
            className={`px-2 py-1 text-[10px] font-mono uppercase tracking-wider rounded-none border cursor-pointer font-semibold transition-colors ${
              hideUnavailable
                ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                : 'bg-[#141414] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0]'
            }`}
          >
            HIDE N/A
          </button>
        </div>
      </div>

      {/* Main Table */}
      <div className="w-full overflow-x-clip">
        {groupedSections.length === 0 ? (
          <div className="p-10 text-center text-[#737373] font-mono text-xs">
            No web surface or passive DNS artifacts match the active filters.
          </div>
        ) : (
          <table className="w-full table-fixed text-left border-separate border-spacing-0 font-mono text-xs">
            <colgroup>
              <col className="w-36 sm:w-56 md:w-64" />
              <col />
              {!isSingle && <col />}
            </colgroup>
            <thead ref={theadRef}>
              <tr className="bg-[#141414] text-[10px] text-[#8c8c8c] uppercase tracking-wider select-none">
                <th
                  style={{ top: 'var(--matrix-sticky-top, 101px)' }}
                  className="sticky z-20 bg-[#141414] shadow-[inset_0_-1px_0_#383838] py-2 px-3 sm:px-4 font-semibold whitespace-nowrap w-36 sm:w-56 md:w-64"
                >
                  Indicator
                </th>
                <th
                  style={{ top: 'var(--matrix-sticky-top, 101px)' }}
                  className="sticky z-20 bg-[#141414] shadow-[inset_0_-1px_0_#383838,inset_1px_0_0_#2e2e2e] py-2 px-3 sm:px-4 font-semibold whitespace-nowrap"
                >
                  <div className="truncate">
                    {!isSingle && <span className="text-[#c30800] font-bold">A: </span>}
                    <span className="text-[#f0f0f0]">{domainA.domainName}</span>
                  </div>
                </th>
                {!isSingle && domainB && (
                  <th
                    style={{ top: 'var(--matrix-sticky-top, 101px)' }}
                    className="sticky z-20 bg-[#141414] shadow-[inset_0_-1px_0_#383838,inset_1px_0_0_#2e2e2e] py-2 px-3 sm:px-4 font-semibold whitespace-nowrap"
                  >
                    <div className="truncate">
                      <span className="text-[#c300bb] font-bold">B: </span>
                      <span className="text-[#f0f0f0]">{domainB.domainName}</span>
                    </div>
                  </th>
                )}
              </tr>
            </thead>
            {groupedSections.map(({ meta, fields }) => {
              const Icon = meta.icon;
              return (
                <tbody key={meta.label}>
                  <tr className="select-none">
                    <td
                      colSpan={isSingle ? 2 : 3}
                      style={{ top: 'calc(var(--matrix-sticky-top, 101px) + var(--matrix-thead-height, 32px))' }}
                      className="sticky z-10 bg-[#0d0d0d] shadow-[inset_0_1px_0_#383838,inset_0_-1px_0_#383838] py-1.5 px-3 sm:px-4 font-mono text-[10px] font-bold text-[#8c8c8c] uppercase tracking-wider"
                    >
                      <div className="flex items-center gap-2">
                        <Icon className="w-3 h-3 text-[#c30800]" />
                        <span className="text-[#f0f0f0]">{meta.label}</span>
                        <span className="text-[#737373] font-normal">({fields.length})</span>
                      </div>
                    </td>
                  </tr>

                  {fields.map((field) => {
                    const isDiff =
                      !isSingle &&
                      (field.status === 'DIFF' || field.status === 'ONLY_A' || field.status === 'ONLY_B');
                    const isArrA = Array.isArray(field.valueA);
                    const isArrB = Array.isArray(field.valueB);
                    const isExpanded = expandedRowIds.has(field.id);

                    const canExpandA = isArrA
                      ? (field.valueA as string[]).length > 4
                      : String(field.valueA ?? '').length > 180;
                    const canExpandB = !isSingle
                      ? isArrB
                        ? (field.valueB as string[]).length > 4
                        : String(field.valueB ?? '').length > 180
                      : false;
                    const canExpandRow = canExpandA || canExpandB;

                    const handleRowClick = () => {
                      if (!canExpandRow) return;
                      if (window.getSelection()?.toString()) return;
                      toggleRowExpand(field.id);
                    };

                    return (
                      <tr
                        key={field.id}
                        onClick={handleRowClick}
                        className={`transition-colors bg-[#181818] hover:bg-[#1f1f1f] ${
                          canExpandRow ? 'cursor-pointer' : ''
                        }`}
                      >
                        <td className="py-2.5 px-3 sm:px-4 align-top w-36 sm:w-56 md:w-64 border-r border-b border-[#2e2e2e]">
                          <div className="flex flex-col gap-0.5 min-w-0">
                            <span className="font-mono text-xs font-bold text-[#f0f0f0] leading-snug">
                              {field.label}
                            </span>
                            {field.rfcOrSpec && (
                              <span className="text-[10px] font-mono text-[#737373]">
                                [{field.rfcOrSpec}]
                              </span>
                            )}
                          </div>
                        </td>

                        <td
                          className={`py-2.5 px-3 sm:px-4 align-top border-b border-[#2e2e2e] ${
                            !isSingle ? 'border-r' : ''
                          } ${isDiff ? 'bg-[#c30800]/5' : ''}`}
                        >
                          {isArrA
                            ? renderArrayValues(field.valueA as string[], isExpanded)
                            : renderSingleValue(field.valueA, isExpanded)}
                        </td>

                        {!isSingle && (
                          <td className={`py-2.5 px-3 sm:px-4 align-top border-b border-[#2e2e2e] ${isDiff ? 'bg-[#c300bb]/5' : ''}`}>
                            {isArrB
                              ? renderArrayValues(field.valueB as string[], isExpanded)
                              : renderSingleValue(field.valueB, isExpanded)}
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              );
            })}
          </table>
        )}
      </div>
    </div>
  );
};
