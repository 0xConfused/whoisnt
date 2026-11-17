// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import {
  WhoisDiffResult,
  FieldDiffItem,
  OsintCategory,
} from '../types';
import { EPP_STATUS_DEFINITIONS } from '../services/whoisDiffService';
import { WEB_RECON_FIELD_IDS } from './OsintWebSurfaceView';
import {
  Search,
  Shield,
  Calendar,
  Server,
  Layers,
  Network,
  Lock,
  Link2,
} from 'lucide-react';

interface WhoisDiffMatrixProps {
  diff: WhoisDiffResult;
}

type FilterCategory = 'all' | OsintCategory;
type StatusFilter = 'all' | 'diff_only' | 'match_only';

const CATEGORY_CONFIG: Record<
  string,
  { label: string; icon: React.FC<{ className?: string }> }
> = {
  attribution: { label: 'ATTRIBUTION PIVOTS', icon: Link2 },
  certificates: { label: 'CERTIFICATES & TLS', icon: Lock },
  network: { label: 'BGP NETWORK (ASN)', icon: Network },
  infrastructure: { label: 'DNS & MAIL INFRA', icon: Server },
  registrar: { label: 'REGISTRAR & SPONSOR', icon: Shield },
  security: { label: 'EPP STATUS LOCKS', icon: Shield },
  lifecycle: { label: 'LIFECYCLE & INCEPTION', icon: Calendar },
};

const isSingleItemUnavailable = (raw: unknown): boolean => {
  if (raw === null || raw === undefined) return true;
  const s = String(raw).trim().toLowerCase();
  if (!s) return true;
  if (
    s === 'unknown' ||
    s === 'n/a' ||
    s === 'na' ||
    s === 'none' ||
    s === 'null' ||
    s === 'undefined' ||
    s === '-' ||
    s === 'undetermined' ||
    s === 'not specified' ||
    s === 'not resolved' ||
    s === 'not available' ||
    s === 'not disclosed' ||
    s === 'not configured / none' ||
    s === 'probe unresolved' ||
    s === 'connection failed' ||
    s === 'unrouted / private' ||
    s === 'undisclosed / hidden' ||
    s === 'protected / redacted' ||
    s === 'protected / registry proxy' ||
    s === 'redacted' ||
    s === 'data redacted' ||
    s === 'redacted for privacy' ||
    s === 'redacted for privacy / proxy' ||
    s === 'redacted / not disclosed' ||
    s === 'none specified' ||
    s === 'none resolved' ||
    s === 'none listed' ||
    s === 'no mx records' ||
    s === 'no mx records listed' ||
    s === 'no spf record' ||
    s === 'no dmarc record' ||
    s === 'no ptr record' ||
    s === 'no caa restriction' ||
    s === 'no records announced' ||
    s === 'no third-party verification tokens detected' ||
    s === 'no common dkim selectors detected' ||
    s === 'unsigned / no ds or dnskey' ||
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
    s === 'no footer copyright notice detected' ||
    s === 'unreachable over http/https' ||
    s.startsWith('blocked by target cors policy')
  ) {
    return true;
  }
  if (
    s.includes('redacted') ||
    s.includes('not disclosed') ||
    s.includes('not available') ||
    s.includes('privacy / proxy') ||
    s.includes('registry proxy')
  ) {
    return true;
  }
  return false;
};

const isValueUnavailable = (val: string | string[] | null | undefined): boolean => {
  if (val === null || val === undefined) return true;
  if (Array.isArray(val)) {
    if (val.length === 0) return true;
    return val.every((item) => {
      const cleaned = String(item).replace(/^(created|updated):\s*/i, '');
      return isSingleItemUnavailable(cleaned);
    });
  }
  return isSingleItemUnavailable(val);
};

export const WhoisDiffMatrix: React.FC<WhoisDiffMatrixProps> = ({ diff }) => {
  const { domainA, domainB, fieldDiffs } = diff;
  const isSingle = Boolean(diff.isSingleDomain || !domainB);

  const [activeCategory, setActiveCategory] = useState<FilterCategory>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [hideUnavailable, setHideUnavailable] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Row collapse / expand management for large fields
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
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const fieldsBeforeCategory = useMemo(() => {
    return fieldDiffs.filter((field) => {
      // Dedicated Web Recon & Passive DNS items belong to the WEB RECON tab
      if (field.category === 'web' || WEB_RECON_FIELD_IDS.has(field.id)) {
        return false;
      }

      // Low-impact filter
      if (field.isLowImpact) {
        return false;
      }

      // Status filter (only relevant in two-domain comparison mode)
      if (!isSingle) {
        if (statusFilter === 'diff_only' && field.status === 'MATCH') {
          return false;
        }
        if (statusFilter === 'match_only' && field.status !== 'MATCH') {
          return false;
        }
      }

      // Hide redacted, unknown, or unavailable rows
      if (
        hideUnavailable &&
        isValueUnavailable(field.valueA) &&
        (isSingle || isValueUnavailable(field.valueB))
      ) {
        return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const strA = Array.isArray(field.valueA) ? field.valueA.join(' ') : String(field.valueA || '');
        const strB = !isSingle
          ? Array.isArray(field.valueB)
            ? field.valueB.join(' ')
            : String(field.valueB || '')
          : '';
        const matchLabel = field.label.toLowerCase().includes(q);
        const matchRfc = (field.rfcOrSpec || '').toLowerCase().includes(q);
        const matchValA = strA.toLowerCase().includes(q);
        const matchValB = strB.toLowerCase().includes(q);
        return matchLabel || matchRfc || matchValA || matchValB;
      }

      return true;
    });
  }, [fieldDiffs, hideUnavailable, statusFilter, searchQuery, isSingle]);

  const filteredFields = useMemo(() => {
    if (activeCategory === 'all') return fieldsBeforeCategory;
    return fieldsBeforeCategory.filter((field) => field.category === activeCategory);
  }, [fieldsBeforeCategory, activeCategory]);

  // Group filtered fields by category and alphabetize sections and rows within each section
  const groupedFields = useMemo(() => {
    const groups: Record<string, FieldDiffItem[]> = {};
    filteredFields.forEach((field) => {
      if (!groups[field.category]) {
        groups[field.category] = [];
      }
      groups[field.category].push(field);
    });

    const sortedGroups: Record<string, FieldDiffItem[]> = {};
    const sortedCategoryKeys = Object.keys(groups).sort((a, b) => {
      const labelA = CATEGORY_CONFIG[a]?.label || a;
      const labelB = CATEGORY_CONFIG[b]?.label || b;
      return labelA.localeCompare(labelB, undefined, { sensitivity: 'base' });
    });

    for (const catKey of sortedCategoryKeys) {
      sortedGroups[catKey] = [...groups[catKey]].sort((a, b) =>
        a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' })
      );
    }

    return sortedGroups;
  }, [filteredFields]);

  const renderArrayValues = (
    fieldId: string,
    values: string[],
    isExpanded: boolean
  ) => {
    if (!values || values.length === 0) {
      return <span className="text-[#737373] italic font-mono text-xs">No records announced</span>;
    }

    const sortedValues = [...values].sort((a, b) =>
      String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' })
    );
    const limit = fieldId === 'status' ? 2 : 3;
    const isOverLimit = sortedValues.length > limit;
    const displayedValues = !isExpanded && isOverLimit ? sortedValues.slice(0, limit) : sortedValues;

    return (
      <div className="space-y-1.5 font-mono text-xs">
        {displayedValues.map((val, idx) => {
          const eppKey = val.toLowerCase().replace(/[^a-z]/g, '');
          const eppDef = fieldId === 'status' ? EPP_STATUS_DEFINITIONS[eppKey] : null;

          return (
            <div key={idx} className="flex flex-col gap-0.5">
              <div className="flex items-center min-w-0">
                <span className="font-mono text-xs break-all text-[#f0f0f0]">
                  {val}
                </span>
              </div>

              {eppDef && (
                <div className="text-[10px] text-[#737373] font-mono leading-snug">
                  {eppDef.desc}
                </div>
              )}
            </div>
          );
        })}

        {isOverLimit && (
          <div className="pt-0.5 text-[10px] font-mono text-[#8c8c8c]">
            {isExpanded
              ? `Showing all ${values.length} records (click to minimize)`
              : `+ ${values.length - limit} more records (click to expand)`}
          </div>
        )}
      </div>
    );
  };

  const renderSingleValue = (
    val: unknown,
    isExpanded: boolean
  ) => {
    const textVal = val !== undefined && val !== null ? String(val) : '';
    const isPresent = textVal.trim().length > 0;

    const isLongText = textVal.length > 180;
    const displayText = isLongText && !isExpanded ? `${textVal.slice(0, 160)}...` : textVal;

    return (
      <div className="flex flex-col gap-1">
        <div className="flex items-center min-w-0">
          <span
            className={`font-mono text-xs break-all ${
              !isPresent ? 'text-[#737373] italic' : 'text-[#f0f0f0]'
            }`}
          >
            {displayText || 'Not configured / None'}
          </span>
        </div>

        {isLongText && (
          <div className="text-[10px] font-mono text-[#8c8c8c]">
            {isExpanded
              ? 'Click to minimize'
              : `Click to expand (${textVal.length} chars)`}
          </div>
        )}
      </div>
    );
  };

  return (
    <div
      ref={containerRef}
      id="whois-diff-matrix-table"
      className="bg-[#141414] border border-[#383838] rounded-none overflow-x-clip flex flex-col relative z-0 isolate mb-6"
    >
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Minimal Category Filter Bar */}
      <div className="px-4 py-2.5 bg-[#141414] flex flex-wrap items-center gap-1.5 border-b border-[#2e2e2e]">
        {[
          { id: 'all', label: 'All', count: fieldsBeforeCategory.length },
          { id: 'attribution', label: 'Attribution', count: fieldsBeforeCategory.filter((f) => f.category === 'attribution').length },
          { id: 'certificates', label: 'Certificates', count: fieldsBeforeCategory.filter((f) => f.category === 'certificates').length },
          { id: 'network', label: 'Network', count: fieldsBeforeCategory.filter((f) => f.category === 'network').length },
          { id: 'infrastructure', label: 'DNS/Mail', count: fieldsBeforeCategory.filter((f) => f.category === 'infrastructure').length },
          { id: 'registrar', label: 'Registrar', count: fieldsBeforeCategory.filter((f) => f.category === 'registrar').length },
          { id: 'security', label: 'EPP Locks', count: fieldsBeforeCategory.filter((f) => f.category === 'security').length },
          { id: 'lifecycle', label: 'Lifecycle', count: fieldsBeforeCategory.filter((f) => f.category === 'lifecycle').length },
        ].map((cat) => (
          <button
            key={cat.id}
            type="button"
            onClick={() => setActiveCategory(cat.id as FilterCategory)}
            className={`px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer transition-colors font-semibold shrink-0 ${
              activeCategory === cat.id
                ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                : 'bg-[#0d0d0d] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0] hover:border-[#383838]'
            }`}
          >
            {cat.label} ({cat.count})
          </button>
        ))}
      </div>

      {/* Compact Search & Filter Bar */}
      <div className="px-4 py-2 bg-[#0d0d0d] border-b border-[#383838] flex flex-wrap items-center justify-between gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="w-3.5 h-3.5 text-[#8c8c8c] absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            maxLength={200}
            placeholder="Filter attributes"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1 bg-[#141414] border border-[#2e2e2e] hover:border-[#383838] rounded-none text-xs text-[#f0f0f0] placeholder-[#737373] focus:outline-none focus:border-[#c30800]/60 font-mono transition-colors"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {!isSingle && (
            <div
              role="group"
              aria-label="Diff status filter"
              className="inline-flex items-center bg-[#0d0d0d] border border-[#383838] rounded-none p-0.5 gap-0.5"
            >
              <button
                type="button"
                onClick={() => setStatusFilter('all')}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded-none border cursor-pointer font-semibold transition-colors ${
                  statusFilter === 'all'
                    ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                    : 'bg-[#141414] text-[#8c8c8c] border-transparent hover:text-[#f0f0f0]'
                }`}
              >
                ALL
              </button>
              <button
                type="button"
                onClick={() => setStatusFilter('diff_only')}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded-none border cursor-pointer font-semibold transition-colors ${
                  statusFilter === 'diff_only'
                    ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                    : 'bg-[#141414] text-[#8c8c8c] border-transparent hover:text-[#f0f0f0]'
                }`}
              >
                DIFFS
              </button>
              <button
                type="button"
                onClick={() => setStatusFilter('match_only')}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded-none border cursor-pointer font-semibold transition-colors ${
                  statusFilter === 'match_only'
                    ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                    : 'bg-[#141414] text-[#8c8c8c] border-transparent hover:text-[#f0f0f0]'
                }`}
              >
                MATCHES
              </button>
            </div>
          )}
          <button
            type="button"
            onClick={() => setHideUnavailable((prev) => !prev)}
            aria-pressed={hideUnavailable}
            title="Hide fields where data is redacted, unknown, or unavailable"
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

      {/* Main Side-by-Side Diff Table */}
      <div className="w-full overflow-x-clip">
        {Object.keys(groupedFields).length === 0 ? (
          <div className="p-10 text-center text-[#737373] font-mono text-xs">
            No OSINT attributes match the active filter criteria.
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
            {(Object.entries(groupedFields) as Array<[string, FieldDiffItem[]]>).map(([catKey, fields]) => {
              const catInfo = CATEGORY_CONFIG[catKey] || { label: catKey.toUpperCase(), icon: Layers };
              const Icon = catInfo.icon;

              return (
                <tbody key={catKey}>
                  {/* Sticky Category Subheader Row */}
                  <tr className="select-none">
                    <td
                      colSpan={isSingle ? 2 : 3}
                      style={{ top: 'calc(var(--matrix-sticky-top, 101px) + var(--matrix-thead-height, 32px))' }}
                      className="sticky z-10 bg-[#0d0d0d] shadow-[inset_0_1px_0_#383838,inset_0_-1px_0_#383838] py-1.5 px-3 sm:px-4 font-mono text-[10px] font-bold text-[#8c8c8c] uppercase tracking-wider"
                    >
                      <div className="flex items-center gap-2">
                        <Icon className="w-3 h-3 text-[#c30800]" />
                        <span className="text-[#f0f0f0]">{catInfo.label}</span>
                        <span className="text-[#737373] font-normal">({fields.length})</span>
                      </div>
                    </td>
                  </tr>

                  {/* Field Indicator Data Rows */}
                  {fields.map((field) => {
                    const isDiff =
                      !isSingle &&
                      (field.status === 'DIFF' || field.status === 'ONLY_A' || field.status === 'ONLY_B');
                    const isArrA = Array.isArray(field.valueA);
                    const isArrB = Array.isArray(field.valueB);
                    const isExpanded = expandedRowIds.has(field.id);

                    const limit = field.id === 'status' ? 2 : 3;
                    const canExpandA = isArrA
                      ? (field.valueA as string[]).length > limit
                      : String(field.valueA ?? '').length > 180;
                    const canExpandB = !isSingle
                      ? isArrB
                        ? (field.valueB as string[]).length > limit
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
                        title={
                          canExpandRow
                            ? isExpanded
                              ? 'Click row to minimize'
                              : 'Click row to expand'
                            : undefined
                        }
                        className={`transition-colors bg-[#181818] hover:bg-[#1f1f1f] ${
                          canExpandRow ? 'cursor-pointer' : ''
                        }`}
                      >
                        {/* Column 1: Indicator Label & RFC */}
                        <td className="py-2.5 px-3 sm:px-4 align-top w-36 sm:w-56 md:w-64 border-r border-b border-[#2e2e2e]">
                          <div className="flex flex-col gap-0.5">
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

                        {/* Column 2: Domain A Value */}
                        <td
                          className={`py-2.5 px-3 sm:px-4 align-top border-b border-[#2e2e2e] ${
                            !isSingle ? 'border-r' : ''
                          } ${isDiff ? 'bg-[#c30800]/5' : ''}`}
                        >
                          {isArrA
                            ? renderArrayValues(
                                field.id,
                                field.valueA as string[],
                                isExpanded
                              )
                            : renderSingleValue(
                                field.valueA,
                                isExpanded
                              )}
                        </td>

                        {/* Column 3: Domain B Value */}
                        {!isSingle && (
                          <td className={`py-2.5 px-3 sm:px-4 align-top border-b border-[#2e2e2e] ${isDiff ? 'bg-[#c300bb]/5' : ''}`}>
                            {isArrB
                              ? renderArrayValues(
                                  field.id,
                                  field.valueB as string[],
                                  isExpanded
                                )
                              : renderSingleValue(
                                  field.valueB,
                                  isExpanded
                                )}
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
