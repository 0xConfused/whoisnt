// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useEffect, useCallback, useTransition, useRef } from 'react';
import { WhoisDiffResult } from './types';
import { fetchAndCompareWhois, sanitizeDomainInput, isValidDomainFormat } from './services/whoisDiffService';
import { WhoisDiffHeader } from './components/WhoisDiffHeader';
import { WhoisDiffInput } from './components/WhoisDiffInput';
import { WhoisDiffMatrix } from './components/WhoisDiffMatrix';
import { OsintTopologyMap } from './components/OsintTopologyMap';
import { OsintTimelineView } from './components/OsintTimelineView';
import { OsintSubdomainIntersection } from './components/OsintSubdomainIntersection';
import { OsintWebSurfaceView } from './components/OsintWebSurfaceView';
import { WhoisRawDiffView } from './components/WhoisRawDiffView';
import { WhoisExportModal } from './components/WhoisExportModal';
import { WhoisFooter } from './components/WhoisFooter';
import { Table, Network, Calendar, Layers, FileCode, Code2 } from 'lucide-react';

type OsintViewMode = 'matrix' | 'topology' | 'timeline' | 'subdomains' | 'web_recon' | 'raw_diff';

const NAMED_PARAM_KEYS = new Set(['a', 'b', 'domainA', 'domainB']);
const FORBIDDEN_PARAM_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function parseSitesFromUrlSearch(search: string): { siteA: string; siteB: string; urlError: string | null } {
  if (!search) return { siteA: '', siteB: '', urlError: null };
  if (search.length > 2048) {
    return { siteA: '', siteB: '', urlError: 'URL query parameters exceed safe maximum length.' };
  }

  const params = new URLSearchParams(search);
  const namedA = params.get('a') || params.get('domainA') || '';
  const namedB = params.get('b') || params.get('domainB') || '';

  const bareTokens: string[] = [];
  for (const [key, value] of params.entries()) {
    const trimmedKey = key.trim();
    if (!trimmedKey || NAMED_PARAM_KEYS.has(trimmedKey) || FORBIDDEN_PARAM_KEYS.has(trimmedKey)) continue;
    if (value === '' || /^https?:\/\//i.test(trimmedKey) || trimmedKey.includes('/') || trimmedKey.includes('?')) {
      bareTokens.push(trimmedKey);
      if (bareTokens.length >= 2) break;
    }
  }

  if (bareTokens.length === 1 && bareTokens[0].includes(',')) {
    const parts = bareTokens[0]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 2);
    bareTokens.splice(0, 1, ...parts);
  }

  const rawA = namedA || bareTokens.shift() || '';
  const rawB = namedB || bareTokens.shift() || '';

  const cleanA = rawA ? sanitizeDomainInput(rawA) : '';
  const cleanB = rawB ? sanitizeDomainInput(rawB) : '';

  const validA = cleanA && isValidDomainFormat(cleanA) ? cleanA : '';
  const validB = cleanB && isValidDomainFormat(cleanB) ? cleanB : '';

  const hasInvalidParam = Boolean((rawA && !validA) || (rawB && !validB));

  return {
    siteA: validA,
    siteB: validB,
    urlError: hasInvalidParam ? 'Invalid or disallowed domain parameter in URL. Only valid public domain names are permitted.' : null,
  };
}

export default function App() {
  const [domainA, setDomainA] = useState<string>('');
  const [domainB, setDomainB] = useState<string>('');
  const [diffResult, setDiffResult] = useState<WhoisDiffResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<OsintViewMode>('matrix');
  const [showExportModal, setShowExportModal] = useState<boolean>(false);

  const [, startTransition] = useTransition();
  const tabBarRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const updateStickyOffsets = () => {
      const headerEl = document.getElementById('crawler-header');
      const headerRectH = headerEl ? headerEl.getBoundingClientRect().height : 65;
      const headerH = Math.floor(headerRectH);
      const tabRectH = tabBarRef.current ? tabBarRef.current.getBoundingClientRect().height : 37;
      const stickyTop = Math.max(0, Math.floor(headerH + tabRectH) - 1);
      document.documentElement.style.setProperty('--topbar-height', `${headerH}px`);
      document.documentElement.style.setProperty('--matrix-sticky-top', `${stickyTop}px`);
    };

    updateStickyOffsets();

    const observer = new ResizeObserver(updateStickyOffsets);
    const headerEl = document.getElementById('crawler-header');
    if (headerEl) observer.observe(headerEl);
    if (tabBarRef.current) observer.observe(tabBarRef.current);
    window.addEventListener('resize', updateStickyOffsets);

    return () => {
      observer.disconnect();
      window.removeEventListener('resize', updateStickyOffsets);
    };
  }, [diffResult]);

  const handleCompare = useCallback(
    async (targetA = domainA, targetB = domainB, syncUrl = true) => {
      const cleanA = sanitizeDomainInput(targetA);
      const cleanB = sanitizeDomainInput(targetB);

      if (!cleanA && !cleanB) {
        setDiffResult(null);
        setError(null);
        return;
      }

      if (targetA.trim() && !isValidDomainFormat(cleanA)) {
        setError('Domain A is invalid or disallowed. Please enter a valid public domain (e.g. example.com).');
        return;
      }
      if (targetB.trim() && !isValidDomainFormat(cleanB)) {
        setError('Domain B is invalid or disallowed. Please enter a valid public domain (e.g. example.org).');
        return;
      }

      if (cleanA && cleanA !== targetA) setDomainA(cleanA);
      if (cleanB && cleanB !== targetB) setDomainB(cleanB);

      if (syncUrl && (cleanA || cleanB)) {
        const nextSearch =
          cleanA && cleanB
            ? `?${encodeURIComponent(cleanA)}&${encodeURIComponent(cleanB)}`
            : `?${encodeURIComponent(cleanA || cleanB)}`;
        if (window.location.search !== nextSearch) {
          window.history.pushState(null, '', `${window.location.pathname}${nextSearch}${window.location.hash}`);
        }
      }

      setIsLoading(true);
      setError(null);

      try {
        const result = await fetchAndCompareWhois(cleanA, cleanB);
        startTransition(() => {
          setDiffResult(result);
          setIsLoading(false);
        });
      } catch (err: any) {
        setIsLoading(false);
        setError(err.message || 'Failed to retrieve authoritative WHOIS & OSINT records.');
      }
    },
    [domainA, domainB]
  );

  const handleCompareRef = useRef(handleCompare);
  handleCompareRef.current = handleCompare;

  // Initial lookup on mount and browser back/forward navigation
  useEffect(() => {
    const syncFromUrl = () => {
      const { siteA, siteB, urlError } = parseSitesFromUrlSearch(window.location.search);
      setDomainA(siteA);
      setDomainB(siteB);
      if ((siteA || siteB) && !urlError) {
        handleCompareRef.current(siteA, siteB, false);
      } else {
        setDiffResult(null);
        setError(urlError);
      }
    };

    syncFromUrl();
    window.addEventListener('popstate', syncFromUrl);
    return () => window.removeEventListener('popstate', syncFromUrl);
  }, []);

  const handleDomainAChange = (val: string) => {
    setDomainA(val);
  };

  const handleDomainBChange = (val: string) => {
    setDomainB(val);
  };

  const handleReset = () => {
    setDomainA('');
    setDomainB('');
    setDiffResult(null);
    setError(null);
    if (window.location.search) {
      window.history.pushState(null, '', `${window.location.pathname}${window.location.hash}`);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d0d0d] text-[#f0f0f0] flex flex-col antialiased selection:bg-[#c30800] selection:text-[#f3f3f7]">
      {/* Top Header with Brand Lock, Export, and Reset */}
      <WhoisDiffHeader
        domainA={diffResult?.isSingleDomain ? (domainB.trim() && !domainA.trim() ? undefined : diffResult.domainA.domainName) : (diffResult?.domainA.domainName || (isValidDomainFormat(sanitizeDomainInput(domainA)) ? sanitizeDomainInput(domainA) : undefined))}
        domainB={diffResult?.isSingleDomain ? (domainB.trim() && !domainA.trim() ? diffResult.domainA.domainName : undefined) : (diffResult?.domainB?.domainName || (isValidDomainFormat(sanitizeDomainInput(domainB)) ? sanitizeDomainInput(domainB) : undefined))}
        isComparing={isLoading}
        hasDiffData={Boolean(diffResult)}
        onOpenExport={() => setShowExportModal(true)}
        onReset={handleReset}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {/* User Input: 2 Side-by-Side Boxes for Domains and Reset Button */}
        <WhoisDiffInput
          domainA={domainA}
          domainB={domainB}
          onChangeDomainA={handleDomainAChange}
          onChangeDomainB={handleDomainBChange}
          onCompare={() => handleCompare(domainA, domainB)}
          isLoading={isLoading}
          error={error}
        />

        {/* Diff Results Container */}
        {diffResult && (
          <div className="space-y-4">
            {/* Single bar tabs navigation */}
            <div
              ref={tabBarRef}
              className="sticky top-[var(--topbar-height,65px)] z-40 bg-[#0d0d0d] flex items-center border-b border-[#383838] pb-0 w-full overflow-x-auto no-scrollbar"
            >
              <div className="flex items-center gap-1 flex-1 flex-wrap sm:flex-nowrap">
                {[
                  { id: 'matrix', label: diffResult.isSingleDomain ? 'OSINT MATRIX' : 'DELTA MATRIX', icon: Table },
                  { id: 'web_recon', label: 'WEB RECON & PDNS', icon: Code2 },
                  { id: 'topology', label: 'TOPOLOGY GRAPH', icon: Network },
                  { id: 'timeline', label: 'INCEPTION TIMELINE', icon: Calendar },
                  { id: 'subdomains', label: 'CT SUBDOMAINS', icon: Layers },
                  { id: 'raw_diff', label: diffResult.isSingleDomain ? 'RAW BUFFER' : 'RAW BUFFER DIFF', icon: FileCode },
                ].map((tab) => {
                  const Icon = tab.icon;
                  const isActive = activeTab === tab.id;

                  return (
                    <button
                      key={tab.id}
                      type="button"
                      id={`tab-${tab.id}-btn`}
                      onClick={() => setActiveTab(tab.id as OsintViewMode)}
                      className={`flex items-center gap-1.5 px-3 py-2 rounded-none text-[11px] font-mono uppercase tracking-wider transition-colors cursor-pointer border-t-2 border-x whitespace-nowrap ${
                        isActive
                          ? 'bg-[#141414] text-[#f0f0f0] border-t-[#c30800] border-x-[#383838] border-b-[#141414] -mb-[1px] font-bold'
                          : 'border-t-transparent border-x-transparent text-[#8c8c8c] hover:text-[#f0f0f0] hover:bg-[#1a1a1a]'
                      }`}
                    >
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#c30800]' : 'text-[#8c8c8c]'}`} />
                      <span>{tab.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Active View Mode */}
            {activeTab === 'matrix' && (
              <WhoisDiffMatrix diff={diffResult} />
            )}

            {activeTab === 'web_recon' && (
              <OsintWebSurfaceView diff={diffResult} />
            )}

            {activeTab === 'topology' && (
              <OsintTopologyMap diff={diffResult} />
            )}

            {activeTab === 'timeline' && (
              <OsintTimelineView diff={diffResult} />
            )}

            {activeTab === 'subdomains' && (
              <OsintSubdomainIntersection diff={diffResult} />
            )}

            {activeTab === 'raw_diff' && (
              <WhoisRawDiffView diff={diffResult} />
            )}
          </div>
        )}

        {/* Empty State when no domains are entered */}
        {!diffResult && !isLoading && !domainA && !domainB && (
          <div className="p-12 text-center bg-[#141414] border border-[#383838] rounded-none shadow-md space-y-3 my-6">
            <div className="w-12 h-12 bg-[#1a1a1a] border border-[#383838] flex items-center justify-center mx-auto mb-2 text-[#c30800]">
              <Table className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-[#f0f0f0]">
              OSINT Difference Engine Idle
            </h3>
            <p className="max-w-md mx-auto text-xs text-[#8c8c8c] font-mono leading-relaxed">
              Enter one or two domain names above to inspect authoritative WHOIS, BGP routing, Certificate Transparency, and web reconnaissance intelligence.
            </p>
          </div>
        )}
      </main>

      {/* Export Modal */}
      {showExportModal && diffResult && (
        <WhoisExportModal diff={diffResult} onClose={() => setShowExportModal(false)} />
      )}

      {/* Consolidated Footer */}
      <WhoisFooter />
    </div>
  );
}
