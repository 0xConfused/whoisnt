// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { Search, Loader2 } from 'lucide-react';
import { sanitizeDomainInput, isValidDomainFormat } from '../services/whoisDiffService';

interface WhoisDiffInputProps {
  domainA: string;
  domainB: string;
  onChangeDomainA: (val: string) => void;
  onChangeDomainB: (val: string) => void;
  onCompare: () => void;
  onReset?: () => void;
  isLoading: boolean;
  error?: string | null;
}

export const WhoisDiffInput: React.FC<WhoisDiffInputProps> = ({
  domainA,
  domainB,
  onChangeDomainA,
  onChangeDomainB,
  onCompare,
  onReset: _onReset,
  isLoading,
  error,
}) => {
  const cleanA = sanitizeDomainInput(domainA);
  const cleanB = sanitizeDomainInput(domainB);
  const isValidA = !domainA || isValidDomainFormat(cleanA);
  const isValidB = !domainB || isValidDomainFormat(cleanB);
  const canCompare = cleanA && cleanB && isValidA && isValidB && !isLoading;

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && canCompare) {
      e.preventDefault();
      onCompare();
    }
  };

  return (
    <div className="bg-[#141414] border border-[#383838] mb-6 shadow-2xl relative">
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />
      
      <div className="p-4 sm:p-5">
        {/* 2 Side-by-Side Domain Boxes and Reset Button */}
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
          {/* Left Box: Domain A */}
          <div className="flex-1 relative">
            <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-[#8c8c8c] mb-1">
              <span className="flex items-center gap-1.5">
                <span className="text-[#f0f0f0] font-bold">Domain A</span>
              </span>
              {domainA && !isValidA && (
                <span className="text-[#c3005a] font-mono">Invalid syntax</span>
              )}
            </div>
            <input
              type="text"
              value={domainA}
              onChange={(e) => onChangeDomainA(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="First domain (e.g. example.com)"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              disabled={isLoading}
              className={`w-full h-10 px-3.5 bg-[#0d0d0d] text-[#f0f0f0] font-mono text-xs border focus:outline-none transition-colors ${
                domainA && !isValidA
                  ? 'border-[#c3005a] focus:border-[#c3005a]'
                  : 'border-[#383838] focus:border-[#c30800]'
              }`}
            />
          </div>

          {/* Right Box: Domain B */}
          <div className="flex-1 relative">
            <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-[#8c8c8c] mb-1">
              <span className="flex items-center gap-1.5">
                <span className="text-[#f0f0f0] font-bold">Domain B</span>
              </span>
              {domainB && !isValidB && (
                <span className="text-[#c3005a] font-mono">Invalid syntax</span>
              )}
            </div>
            <input
              type="text"
              value={domainB}
              onChange={(e) => onChangeDomainB(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Second domain (e.g. example.org)"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              disabled={isLoading}
              className={`w-full h-10 px-3.5 bg-[#0d0d0d] text-[#f0f0f0] font-mono text-xs border focus:outline-none transition-colors ${
                domainB && !isValidB
                  ? 'border-[#c3005a] focus:border-[#c3005a]'
                  : 'border-[#383838] focus:border-[#c300bb]'
              }`}
            />
          </div>

          {/* Search Button */}
          <div className="shrink-0 self-end md:self-auto pt-0 md:pt-4">
            <button
              id="whois-search-btn"
              type="button"
              onClick={onCompare}
              disabled={!canCompare || isLoading}
              title="Run OSINT Reconnaissance Comparison"
              aria-label="Run OSINT Reconnaissance Comparison"
              className="h-10 px-5 text-xs font-mono font-bold flex items-center justify-center gap-2 bg-gradient-to-r from-[#c30800] to-[#770500] hover:from-[#f60a00] hover:to-[#770500] text-[#f3f3f7] border border-[#c30800] shadow-sm transition-all cursor-pointer uppercase tracking-wider disabled:opacity-40 disabled:cursor-not-allowed rounded-none"
            >
              {isLoading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin text-[#f3f3f7]" />
              ) : (
                <Search className="w-3.5 h-3.5 text-[#f3f3f7]" />
              )}
              <span>{isLoading ? 'SEARCHING...' : 'SEARCH'}</span>
            </button>
          </div>
        </div>

        {/* Loading Indicator or Error */}
        {isLoading && (
          <div className="mt-3 pt-3 border-t border-[#2e2e2e] flex items-center gap-2 text-xs font-mono text-[#8c8c8c]">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-[#c30800]" />
            <span>AGGREGATING WHOIS, REVERSE PIVOTS, CERTIFICATE TRANSPARENCY &amp; BGP NETWORK OSINT...</span>
          </div>
        )}

        {error && !isLoading && (
          <div className="mt-3 pt-3 border-t border-[#2e2e2e] flex items-center gap-2 text-xs font-mono text-[#c3005a]">
            <span>ERROR: {error}</span>
          </div>
        )}
      </div>
    </div>
  );
};
