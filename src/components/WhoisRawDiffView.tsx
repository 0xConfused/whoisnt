// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useMemo, useRef, useEffect } from 'react';
import { WhoisDiffResult } from '../types';
import { Copy, Check, Split, AlignLeft, Lock, Unlock } from 'lucide-react';

interface WhoisRawDiffViewProps {
  diff: WhoisDiffResult;
}

interface SideBySideRow {
  leftLine?: number;
  leftText: string;
  leftType: 'same' | 'delete' | 'empty';
  rightLine?: number;
  rightText: string;
  rightType: 'same' | 'add' | 'empty';
}

export const WhoisRawDiffView: React.FC<WhoisRawDiffViewProps> = ({ diff }) => {
  const { domainA, domainB, rawTextDiff } = diff;
  const isSingle = Boolean(diff.isSingleDomain || !domainB);
  const [viewMode, setViewMode] = useState<'unified' | 'sideBySide'>('unified');
  const [isScrollLocked, setIsScrollLocked] = useState<boolean>(true);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const leftPaneRef = useRef<HTMLPreElement | null>(null);
  const rightPaneRef = useRef<HTMLPreElement | null>(null);
  const syncingSourceRef = useRef<'left' | 'right' | null>(null);
  const syncRafRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (syncRafRef.current !== null) {
        cancelAnimationFrame(syncRafRef.current);
      }
    };
  }, []);

  const handleCopy = (content: string, section: string) => {
    try {
      navigator.clipboard.writeText(content);
      setCopiedSection(section);
      setTimeout(() => setCopiedSection(null), 1800);
    } catch {}
  };

  const handlePaneScroll = (source: 'left' | 'right') => {
    if (!isScrollLocked) return;
    if (syncingSourceRef.current && syncingSourceRef.current !== source) return;

    const srcEl = source === 'left' ? leftPaneRef.current : rightPaneRef.current;
    const dstEl = source === 'left' ? rightPaneRef.current : leftPaneRef.current;
    if (!srcEl || !dstEl) return;

    syncingSourceRef.current = source;
    dstEl.scrollTop = srcEl.scrollTop;
    dstEl.scrollLeft = srcEl.scrollLeft;

    if (syncRafRef.current !== null) {
      cancelAnimationFrame(syncRafRef.current);
    }
    syncRafRef.current = requestAnimationFrame(() => {
      syncingSourceRef.current = null;
      syncRafRef.current = null;
    });
  };

  const toggleScrollLock = () => {
    setIsScrollLocked((prev) => {
      const next = !prev;
      if (next && leftPaneRef.current && rightPaneRef.current) {
        requestAnimationFrame(() => {
          if (!leftPaneRef.current || !rightPaneRef.current) return;
          syncingSourceRef.current = 'left';
          rightPaneRef.current.scrollTop = leftPaneRef.current.scrollTop;
          rightPaneRef.current.scrollLeft = leftPaneRef.current.scrollLeft;
          requestAnimationFrame(() => {
            syncingSourceRef.current = null;
          });
        });
      }
      return next;
    });
  };

  const sideBySideRows = useMemo<SideBySideRow[]>(() => {
    const rows: SideBySideRow[] = [];
    let pendingDeletes: Array<{ line?: number; text: string }> = [];
    let pendingAdds: Array<{ line?: number; text: string }> = [];

    const flushHunk = () => {
      const len = Math.max(pendingDeletes.length, pendingAdds.length);
      for (let i = 0; i < len; i++) {
        const del = pendingDeletes[i];
        const add = pendingAdds[i];
        rows.push({
          leftLine: del?.line,
          leftText: del ? del.text : '',
          leftType: del ? 'delete' : 'empty',
          rightLine: add?.line,
          rightText: add ? add.text : '',
          rightType: add ? 'add' : 'empty',
        });
      }
      pendingDeletes = [];
      pendingAdds = [];
    };

    for (const line of rawTextDiff) {
      if (line.type === 'header') continue;
      if (line.type === 'same') {
        flushHunk();
        const text = line.text.startsWith('  ') ? line.text.slice(2) : line.text;
        rows.push({
          leftLine: line.lineA,
          leftText: text,
          leftType: 'same',
          rightLine: line.lineB,
          rightText: text,
          rightType: 'same',
        });
      } else if (line.type === 'delete') {
        pendingDeletes.push({
          line: line.lineA,
          text: line.text.startsWith('- ') ? line.text.slice(2) : line.text,
        });
      } else if (line.type === 'add') {
        pendingAdds.push({
          line: line.lineB,
          text: line.text.startsWith('+ ') ? line.text.slice(2) : line.text,
        });
      }
    }
    flushHunk();

    return rows;
  }, [rawTextDiff]);

  const fullUnifiedText = rawTextDiff.map((l) => l.text).join('\n');
  const addCount = rawTextDiff.filter((l) => l.type === 'add').length;
  const delCount = rawTextDiff.filter((l) => l.type === 'delete').length;
  const sameCount = rawTextDiff.filter((l) => l.type === 'same').length;

  return (
    <div id="raw-buffer-diff-view" className="bg-[#141414] border border-[#383838] rounded-none overflow-hidden flex flex-col relative mb-6">
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Minimal Toolbar: Stats, View Mode Toggle & Copy */}
      <div className="px-4 py-2.5 bg-[#141414] flex flex-wrap items-center justify-between gap-3 border-b border-[#383838] font-mono">
        <div className="flex flex-wrap items-center gap-3 text-[10px] text-[#8c8c8c]">
          {isSingle ? (
            <>
              <span className="text-[#c30800] font-bold">{domainA.domainName}</span>
              <span>{sameCount} lines</span>
            </>
          ) : (
            <>
              <span className="text-[#c30800] font-bold">-{delCount} deletions</span>
              <span className="text-[#c300bb] font-bold">+{addCount} additions</span>
              <span>{sameCount} identical</span>
            </>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {!isSingle && (
            <div
              role="group"
              aria-label="Raw diff view mode"
              className="inline-flex items-center bg-[#0d0d0d] border border-[#383838] rounded-none p-0.5 gap-0.5"
            >
              <button
                type="button"
                onClick={() => setViewMode('unified')}
                className={`flex items-center gap-1 px-2 py-0.5 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer font-semibold transition-colors ${
                  viewMode === 'unified'
                    ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                    : 'bg-[#141414] text-[#8c8c8c] border-transparent hover:text-[#f0f0f0]'
                }`}
              >
                <AlignLeft className="w-3 h-3 text-[#c30800]" />
                <span>Unified</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('sideBySide')}
                className={`flex items-center gap-1 px-2 py-0.5 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer font-semibold transition-colors ${
                  viewMode === 'sideBySide'
                    ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                    : 'bg-[#141414] text-[#8c8c8c] border-transparent hover:text-[#f0f0f0]'
                }`}
              >
                <Split className="w-3 h-3 text-[#c30800]" />
                <span>Side-by-Side</span>
              </button>
            </div>
          )}

          {!isSingle && viewMode === 'sideBySide' ? (
            <button
              type="button"
              onClick={toggleScrollLock}
              aria-pressed={isScrollLocked}
              title="Lock scrolling so both buffers scroll together and stay aligned on the same lines"
              className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer font-semibold transition-colors ${
                isScrollLocked
                  ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                  : 'bg-[#0d0d0d] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0]'
              }`}
            >
              {isScrollLocked ? (
                <Lock className="w-3 h-3 text-[#c30800]" />
              ) : (
                <Unlock className="w-3 h-3 text-[#8c8c8c]" />
              )}
              <span>LOCK SCROLL</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => handleCopy(isSingle ? (domainA.rawText || fullUnifiedText) : fullUnifiedText, 'unified')}
              className="flex items-center gap-1 px-2 py-1 text-[10px] font-mono uppercase tracking-wider border border-[#383838] bg-[#0d0d0d] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer"
            >
              {copiedSection === 'unified' ? (
                <>
                  <Check className="w-3 h-3 text-[#bbc300]" />
                  <span>COPIED</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>COPY</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Content Area */}
      {(isSingle || viewMode === 'unified') ? (
        <div className="p-4 bg-[#0d0d0d] overflow-x-auto max-h-[600px] overflow-y-auto custom-scrollbar font-mono text-xs">
          {rawTextDiff.length === 0 ? (
            <div className="text-[#737373] py-12 text-center">No raw difference recorded between records.</div>
          ) : (
            <pre className="text-left leading-relaxed">
              {rawTextDiff.map((line, idx) => {
                let lineClass = 'text-[#8c8c8c]';
                if (line.type === 'header') {
                  lineClass = line.text.startsWith('---')
                    ? 'text-[#c30800] font-bold bg-[#c30800]/10 px-1 block'
                    : 'text-[#c300bb] font-bold bg-[#c300bb]/10 px-1 block';
                } else if (line.type === 'delete') {
                  lineClass = 'text-[#c30800] bg-[#c30800]/10 px-1 block border-l-2 border-[#c30800]';
                } else if (line.type === 'add') {
                  lineClass = 'text-[#c300bb] bg-[#c300bb]/10 px-1 block border-l-2 border-[#c300bb]';
                }

                return (
                  <div key={idx} className={`${lineClass} select-text font-mono text-xs`}>
                    <span className="text-[#383838] select-none w-10 inline-block text-right pr-3 font-mono">
                      {line.lineA || line.lineB || ''}
                    </span>
                    <span>{line.text}</span>
                  </div>
                );
              })}
            </pre>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-[#2e2e2e] bg-[#0d0d0d]">
          {/* Domain A Raw */}
          <div className="p-4 flex flex-col min-w-0">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#2e2e2e]">
              <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-[#c30800]">
                <span>{domainA.domainName} [RAW BUFFER]</span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(domainA.rawText || '', 'rawA')}
                className="px-2 py-0.5 text-[10px] font-mono border border-[#383838] bg-[#141414] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer flex items-center gap-1"
              >
                {copiedSection === 'rawA' ? <Check className="w-2.5 h-2.5 text-[#bbc300]" /> : <Copy className="w-2.5 h-2.5" />}
                <span>{copiedSection === 'rawA' ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>
            {isScrollLocked && sideBySideRows.length > 0 ? (
              <pre
                ref={leftPaneRef}
                onScroll={() => handlePaneScroll('left')}
                className="text-xs font-mono text-[#8c8c8c] overflow-auto max-h-[500px] custom-scrollbar select-text whitespace-pre"
              >
                <div className="min-w-max">
                  {sideBySideRows.map((row, idx) => {
                    const rowClass =
                      row.leftType === 'delete'
                        ? 'text-[#c30800] bg-[#c30800]/10 border-l-2 border-[#c30800]'
                        : row.leftType === 'empty'
                        ? 'bg-[#141414]/60 text-[#383838]'
                        : 'text-[#8c8c8c]';
                    return (
                      <div key={idx} className={`h-5 leading-5 px-1 flex items-center ${rowClass}`}>
                        <span className="text-[#383838] select-none w-9 shrink-0 inline-block text-right pr-2.5">
                          {row.leftLine ?? ''}
                        </span>
                        <span>{row.leftType === 'empty' ? ' ' : row.leftText}</span>
                      </div>
                    );
                  })}
                </div>
              </pre>
            ) : (
              <pre
                ref={leftPaneRef}
                onScroll={() => handlePaneScroll('left')}
                className="text-xs font-mono text-[#8c8c8c] overflow-x-auto max-h-[500px] overflow-y-auto custom-scrollbar whitespace-pre-wrap select-text leading-relaxed"
              >
                {domainA.rawText || 'No raw buffer recorded for Domain A.'}
              </pre>
            )}
          </div>

          {/* Domain B Raw */}
          {domainB && (
          <div className="p-4 flex flex-col min-w-0">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#2e2e2e]">
              <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-[#c300bb]">
                <span>{domainB.domainName} [RAW BUFFER]</span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(domainB.rawText || '', 'rawB')}
                className="px-2 py-0.5 text-[10px] font-mono border border-[#383838] bg-[#141414] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer flex items-center gap-1"
              >
                {copiedSection === 'rawB' ? <Check className="w-2.5 h-2.5 text-[#bbc300]" /> : <Copy className="w-2.5 h-2.5" />}
                <span>{copiedSection === 'rawB' ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>
            {isScrollLocked && sideBySideRows.length > 0 ? (
              <pre
                ref={rightPaneRef}
                onScroll={() => handlePaneScroll('right')}
                className="text-xs font-mono text-[#8c8c8c] overflow-auto max-h-[500px] custom-scrollbar select-text whitespace-pre"
              >
                <div className="min-w-max">
                  {sideBySideRows.map((row, idx) => {
                    const rowClass =
                      row.rightType === 'add'
                        ? 'text-[#c300bb] bg-[#c300bb]/10 border-l-2 border-[#c300bb]'
                        : row.rightType === 'empty'
                        ? 'bg-[#141414]/60 text-[#383838]'
                        : 'text-[#8c8c8c]';
                    return (
                      <div key={idx} className={`h-5 leading-5 px-1 flex items-center ${rowClass}`}>
                        <span className="text-[#383838] select-none w-9 shrink-0 inline-block text-right pr-2.5">
                          {row.rightLine ?? ''}
                        </span>
                        <span>{row.rightType === 'empty' ? ' ' : row.rightText}</span>
                      </div>
                    );
                  })}
                </div>
              </pre>
            ) : (
              <pre
                ref={rightPaneRef}
                onScroll={() => handlePaneScroll('right')}
                className="text-xs font-mono text-[#8c8c8c] overflow-x-auto max-h-[500px] overflow-y-auto custom-scrollbar whitespace-pre-wrap select-text leading-relaxed"
              >
                {domainB.rawText || 'No raw buffer recorded for Domain B.'}
              </pre>
            )}
          </div>
          )}
        </div>
      )}
    </div>
  );
};
