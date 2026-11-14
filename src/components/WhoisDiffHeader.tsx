// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useEffect, useRef } from 'react';
import { Download, RotateCcw } from 'lucide-react';
import { SkullLogo } from './SkullLogo';

interface WhoisDiffHeaderProps {
  domainA?: string;
  domainB?: string;
  isComparing?: boolean;
  hasDiffData?: boolean;
  onOpenExport?: () => void;
  onReset?: () => void;
}

const BRAND_NAME = '0xCONFUSED';
const SCRAMBLE_CHARS = '!@#$%^&*<>[]_01';

export const WhoisDiffHeader: React.FC<WhoisDiffHeaderProps> = ({
  domainA,
  domainB,
  isComparing,
  hasDiffData,
  onOpenExport,
  onReset,
}) => {
  const [scrambleText, setScrambleText] = useState<string>(BRAND_NAME);
  const lastHoverScrambleRef = useRef<number>(0);
  const scrambleIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const runScramble = () => {
    if (scrambleIntervalRef.current) {
      clearInterval(scrambleIntervalRef.current);
    }
    let iteration = 0;
    scrambleIntervalRef.current = setInterval(() => {
      setScrambleText(
        BRAND_NAME.split('')
          .map((_char, index) => {
            if (index < iteration) {
              return BRAND_NAME[index];
            }
            return SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
          })
          .join('')
      );
      if (iteration >= BRAND_NAME.length) {
        if (scrambleIntervalRef.current) {
          clearInterval(scrambleIntervalRef.current);
          scrambleIntervalRef.current = null;
        }
        setScrambleText(BRAND_NAME);
      }
      iteration += 1 / 3;
    }, 30);
  };

  const handleMouseEnter = () => {
    const now = Date.now();
    if (now - lastHoverScrambleRef.current < 2000) return;
    lastHoverScrambleRef.current = now;
    runScramble();
  };

  useEffect(() => {
    runScramble();
    return () => {
      if (scrambleIntervalRef.current) {
        clearInterval(scrambleIntervalRef.current);
      }
    };
  }, []);

  return (
    <header id="crawler-header" className="topbar">
      <div className="topbar-inner">
        {/* Brand Lock */}
        <div className="brand">
          <div
            className="brand-logo-slot cursor-pointer"
            onMouseEnter={handleMouseEnter}
          >
            <a
              href="https://www.0xconfused.com/"
              target="_blank"
              rel="noopener noreferrer"
              data-bypass-warning="true"
              className="brand-logo-link block w-full h-full"
              aria-label="0xCONFUSED Website"
            >
              <div className="brand-logo-inner" aria-hidden="true">
                <SkullLogo size={64} className="w-16 h-16 object-contain opacity-100" />
              </div>
            </a>
          </div>

          <div className="brand-text-wrap">
            <div className="brand-title-row">
              <h1
                className="brand-glitch-text font-glitch"
                id="brandGlitchText"
                data-text="0xCONFUSED"
                onMouseEnter={handleMouseEnter}
              >
                <a
                  href="https://www.0xconfused.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  data-bypass-warning="true"
                  className="no-underline text-inherit inline-block"
                  aria-label="0xCONFUSED Website"
                >
                  <span className="brand-title">{scrambleText}</span>
                </a>
              </h1>
              <span className="brand-mod font-mono">./whoisnt</span>
            </div>
            <p className="brand-tagline">
              {domainA && domainB ? (
                <span className="flex items-center gap-1.5 text-[#f0f0f0] min-w-0">
                  <span className="text-[#8c8c8c]">TARGETS:</span>
                  <span className="text-[#f0f0f0] font-bold underline decoration-[#c30800] truncate max-w-[180px] sm:max-w-xs" title={domainA}>
                    {domainA}
                  </span>
                  <span className="text-[#737373]">VS</span>
                  <span className="text-[#f0f0f0] font-bold underline decoration-[#c300bb] truncate max-w-[180px] sm:max-w-xs" title={domainB}>
                    {domainB}
                  </span>
                </span>
              ) : (
                'Authoritative WHOIS, Reverse Pivots & Certificate Intelligence Engine'
              )}
            </p>
          </div>
        </div>

        {/* Topbar Actions */}
        <div className="topbar-actions">
          {/* Engine Status */}
          <div className="flex flex-col items-start md:items-end">
            <span className="text-[10px] uppercase tracking-widest text-[#8c8c8c] font-mono font-semibold">
              Engine Status
            </span>
            <span
              id="crawler-status-badge"
              className={`text-xs font-mono font-bold ${
                isComparing
                  ? 'text-[#c30800]'
                  : hasDiffData
                  ? 'text-[#bbc300]'
                  : 'text-[#8c8c8c]'
              }`}
            >
              {isComparing ? 'ANALYZING' : hasDiffData ? 'READY' : 'STANDBY'}
            </span>
          </div>

          {/* Export Button in Header */}
          {hasDiffData && onOpenExport && (
            <button
              type="button"
              onClick={onOpenExport}
              title="Export Diff Intelligence"
              className="btn btn-secondary flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-mono font-bold transition-all uppercase tracking-wider bg-[#141414] hover:bg-[#262626] text-[#f0f0f0] border border-[#383838] hover:border-[#c30800] cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-[#c30800]" />
              <span>EXPORT</span>
            </button>
          )}

          {/* Rightmost Square Reset Button with Icon matching crawler.0xconfused.com */}
          {onReset && (
            <button
              id="reset-whois-diff-btn"
              type="button"
              onClick={onReset}
              title="Reset All Recon Data"
              aria-label="Reset All Recon Data"
              className="btn btn-secondary icon-btn text-[#8c8c8c] hover:text-[#f0f0f0] cursor-pointer"
            >
              <RotateCcw className="w-4 h-4 text-[#c30800]" />
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
