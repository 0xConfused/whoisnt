// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useMemo, useRef, useCallback } from 'react';
import { WhoisDiffResult } from '../types';
import { parseFlexibleDateMs } from '../utils/dateUtils';

interface OsintTimelineViewProps {
  diff: WhoisDiffResult;
}

interface TimelineEvent {
  id: string;
  domainKey: 'A' | 'B';
  domainName: string;
  label: string;
  dateStr: string;
  timestamp: number;
  type: 'created' | 'updated' | 'expires';
  isSignificant?: boolean;
  notes?: string;
}

export const OsintTimelineView: React.FC<OsintTimelineViewProps> = ({ diff }) => {
  const { domainA, domainB } = diff;
  const isSingle = Boolean(diff.isSingleDomain || !domainB);
  const [hoveredEventId, setHoveredEventId] = useState<string | null>(null);
  const hitTargetsRef = useRef<Record<string, { badge: HTMLSpanElement | null; pin: HTMLDivElement | null }>>({});

  const registerTarget = useCallback(
    (id: string, part: 'badge' | 'pin') => (el: HTMLSpanElement | HTMLDivElement | null) => {
      if (!hitTargetsRef.current[id]) {
        hitTargetsRef.current[id] = { badge: null, pin: null };
      }
      if (part === 'badge') {
        hitTargetsRef.current[id].badge = el as HTMLSpanElement | null;
      } else {
        hitTargetsRef.current[id].pin = el as HTMLDivElement | null;
      }
    },
    []
  );

  const handleRailMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const x = e.clientX;
    const y = e.clientY;
    let bestId: string | null = null;
    let bestDistSq = Infinity;

    const entries = Object.entries(hitTargetsRef.current) as Array<
      [string, { badge: HTMLSpanElement | null; pin: HTMLDivElement | null }]
    >;
    for (const [id, refs] of entries) {
      const candidates: Array<{ rect: DOMRect; pad: number }> = [];
      if (refs.badge) candidates.push({ rect: refs.badge.getBoundingClientRect(), pad: 1 });
      if (refs.pin) candidates.push({ rect: refs.pin.getBoundingClientRect(), pad: 3 });

      for (const { rect, pad } of candidates) {
        if (rect.width === 0 || rect.height === 0) continue;
        if (
          x >= rect.left - pad &&
          x <= rect.right + pad &&
          y >= rect.top - pad &&
          y <= rect.bottom + pad
        ) {
          const cx = rect.left + rect.width / 2;
          const cy = rect.top + rect.height / 2;
          const distSq = (x - cx) * (x - cx) + (y - cy) * (y - cy);
          if (distSq < bestDistSq) {
            bestDistSq = distSq;
            bestId = id;
          }
        }
      }
    }

    setHoveredEventId((prev) => (prev === bestId ? prev : bestId));
  }, []);

  const formatDateUtc = (ts: number): string => {
    const iso = new Date(ts).toISOString();
    return iso.endsWith('T00:00:00.000Z')
      ? iso.slice(0, 10)
      : `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
  };

  const { events, minTs, maxTs } = useMemo(() => {
    const list: TimelineEvent[] = [];

    // Domain A events
    if (domainA.createdDate) {
      const ts = parseFlexibleDateMs(domainA.createdDate);
      if (ts !== null && !isNaN(ts)) {
        list.push({
          id: 'created_a',
          domainKey: 'A',
          domainName: domainA.domainName,
          label: 'Domain Inception (Registration)',
          dateStr: formatDateUtc(ts),
          timestamp: ts,
          type: 'created',
          isSignificant: true,
          notes: domainA.domainAgeFormatted || 'Inception record',
        });
      }
    }

    if (domainA.updatedDate) {
      const ts = parseFlexibleDateMs(domainA.updatedDate);
      if (ts !== null && !isNaN(ts)) {
        list.push({
          id: 'updated_a',
          domainKey: 'A',
          domainName: domainA.domainName,
          label: 'Registry State Synchronization',
          dateStr: formatDateUtc(ts),
          timestamp: ts,
          type: 'updated',
        });
      }
    }

    if (domainA.expiresDate) {
      const ts = parseFlexibleDateMs(domainA.expiresDate);
      if (ts !== null && !isNaN(ts)) {
        list.push({
          id: 'expires_a',
          domainKey: 'A',
          domainName: domainA.domainName,
          label: 'Registry Expiration Horizon',
          dateStr: new Date(ts).toISOString().split('T')[0],
          timestamp: ts,
          type: 'expires',
          isSignificant: true,
          notes: `${domainA.daysUntilExpiration || 0} days remaining (${(domainA.expirationStatus || 'active').toUpperCase()})`,
        });
      }
    }

    // Domain B events
    if (domainB && !isSingle) {
      if (domainB.createdDate) {
        const ts = parseFlexibleDateMs(domainB.createdDate);
        if (ts !== null && !isNaN(ts)) {
          list.push({
            id: 'created_b',
            domainKey: 'B',
            domainName: domainB.domainName,
            label: 'Domain Inception (Registration)',
            dateStr: formatDateUtc(ts),
            timestamp: ts,
            type: 'created',
            isSignificant: true,
            notes: domainB.domainAgeFormatted || 'Inception record',
          });
        }
      }

      if (domainB.updatedDate) {
        const ts = parseFlexibleDateMs(domainB.updatedDate);
        if (ts !== null && !isNaN(ts)) {
          list.push({
            id: 'updated_b',
            domainKey: 'B',
            domainName: domainB.domainName,
            label: 'Registry State Synchronization',
            dateStr: formatDateUtc(ts),
            timestamp: ts,
            type: 'updated',
          });
        }
      }

      if (domainB.expiresDate) {
        const ts = parseFlexibleDateMs(domainB.expiresDate);
        if (ts !== null && !isNaN(ts)) {
          list.push({
            id: 'expires_b',
            domainKey: 'B',
            domainName: domainB.domainName,
            label: 'Registry Expiration Horizon',
            dateStr: new Date(ts).toISOString().split('T')[0],
            timestamp: ts,
            type: 'expires',
            isSignificant: true,
            notes: `${domainB.daysUntilExpiration || 0} days remaining (${(domainB.expirationStatus || 'active').toUpperCase()})`,
          });
        }
      }
    }

    // Now marker
    const nowTs = Date.now();
    const timestamps = list.map((e) => e.timestamp);
    timestamps.push(nowTs);

    const min = Math.min(...timestamps);
    const max = Math.max(...timestamps);

    const span = Math.max(86400000 * 30, max - min);
    const padMin = min - span * 0.05;
    const padMax = max + span * 0.05;

    return {
      events: list.sort((a, b) => a.timestamp - b.timestamp),
      minTs: padMin,
      maxTs: padMax,
    };
  }, [domainA, domainB, isSingle]);

  const getPercentage = (ts: number) => {
    const total = maxTs - minTs;
    if (total <= 0) return 50;
    const pct = ((ts - minTs) / total) * 100;
    return Math.max(6, Math.min(94, pct));
  };

  const computeDomainTrackEvents = (domainKey: 'A' | 'B') => {
    const domainEvents = events
      .filter((e) => e.domainKey === domainKey)
      .map((ev) => ({ ev, pos: getPercentage(ev.timestamp), tier: 0 }));

    const tierLastPos = [-Infinity, -Infinity, -Infinity];
    for (const curr of domainEvents) {
      let chosenTier = -1;
      for (let t = 0; t < tierLastPos.length; t++) {
        if (curr.pos - tierLastPos[t] >= 13) {
          chosenTier = t;
          break;
        }
      }
      if (chosenTier === -1) {
        let bestTier = 0;
        let bestGap = -Infinity;
        for (let t = 0; t < tierLastPos.length; t++) {
          const gap = curr.pos - tierLastPos[t];
          if (gap > bestGap) {
            bestGap = gap;
            bestTier = t;
          }
        }
        chosenTier = bestTier;
      }
      curr.tier = chosenTier;
      tierLastPos[chosenTier] = curr.pos;
    }
    return domainEvents;
  };

  const trackEventsA = computeDomainTrackEvents('A');
  const trackEventsB = computeDomainTrackEvents('B');

  const getStemHeight = (tier: number) => {
    if (tier === 2) return '42px';
    if (tier === 1) return '24px';
    return '8px';
  };

  const getShortTag = (type: TimelineEvent['type']) => {
    if (type === 'created') return 'REG';
    if (type === 'expires') return 'EXP';
    return 'UPD';
  };

  return (
    <div id="timeline-recon-view" className="bg-[#141414] border border-[#383838] rounded-none overflow-hidden flex flex-col relative z-0 isolate mb-6">
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Minimal Toolbar */}
      <div className="px-4 py-2.5 bg-[#141414] border-b border-[#383838] flex flex-wrap items-center justify-between gap-3 text-[10px] font-mono text-[#8c8c8c]">
        <div className="flex flex-wrap items-center gap-4">
          <span>
            <strong className="text-[#c30800]">{domainA.domainName}</strong>{!isSingle ? ' [A]' : ''}
          </span>
          {domainB && !isSingle && (
            <span>
              <strong className="text-[#c300bb]">{domainB.domainName}</strong> [B]
            </span>
          )}
        </div>
      </div>

      {/* Main Unified Timeline Canvas */}
      <div className="p-4 sm:p-5 bg-[#0d0d0d]">
        {/* Single Unified Dual-Side Timeline Rail */}
        <div
          onMouseMove={handleRailMouseMove}
          onMouseLeave={() => setHoveredEventId(null)}
          className="relative h-44 bg-[#141414] border border-[#2e2e2e] overflow-hidden select-none"
        >
          {/* Shared Horizontal Center Rail */}
          <div className="absolute left-0 right-0 top-1/2 -translate-y-1/2 h-[1px] bg-[#383838] pointer-events-none" />

          {/* Track Labels */}
          <span className="absolute top-1.5 left-2.5 text-[9px] font-mono uppercase tracking-wider text-[#c30800]/80 pointer-events-none">
            {isSingle ? domainA.domainName : `[A] ${domainA.domainName}`}
          </span>
          {domainB && !isSingle && (
            <span className="absolute bottom-1.5 left-2.5 text-[9px] font-mono uppercase tracking-wider text-[#c300bb]/80 pointer-events-none">
              [B] {domainB.domainName}
            </span>
          )}

          {/* Present (NOW) Marker Line */}
          <div
            style={{ left: `${getPercentage(Date.now())}%` }}
            className="absolute top-0 bottom-0 w-[1px] border-dashed border-l border-[#737373] z-0 pointer-events-none"
          >
            <span className="absolute top-1.5 left-1 text-[8px] font-mono text-[#737373] uppercase tracking-wider">
              NOW
            </span>
          </div>

          {/* Domain A Pins (Above Center Rail) */}
          {trackEventsA.map(({ ev, pos, tier }) => {
            const isHovered = hoveredEventId === ev.id;
            let pinColor = 'bg-[#8c8c8c] border-[#505050]';
            if (ev.type === 'created') {
              pinColor = 'bg-[#c30800] border-[#f60a00]';
            } else if (ev.type === 'expires') {
              pinColor = 'bg-[#bbc300] border-[#bbc300]';
            }

            return (
              <div
                key={ev.id}
                style={{ left: `${pos}%`, bottom: '50%' }}
                className={`absolute -translate-x-1/2 flex flex-col items-center pointer-events-none ${
                  isHovered ? 'z-30' : 'z-10'
                }`}
              >
                <span
                  ref={registerTarget(ev.id, 'badge')}
                  className={`pointer-events-auto cursor-pointer text-[9px] font-mono mb-1 whitespace-nowrap px-1 border transition-colors ${
                    isHovered
                      ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                      : 'bg-[#0d0d0d]/90 text-[#8c8c8c] border-[#2e2e2e]/60'
                  }`}
                >
                  {getShortTag(ev.type)} {ev.dateStr.slice(0, 10)}
                </span>
                <div
                  ref={registerTarget(ev.id, 'pin')}
                  className={`pointer-events-auto cursor-pointer w-2.5 h-2.5 border transition-transform ${pinColor} ${
                    isHovered ? 'scale-125 border-[#f0f0f0]' : ''
                  }`}
                />
                <div
                  style={{ height: getStemHeight(tier) }}
                  className="w-[1px] bg-[#c30800]/60 pointer-events-none"
                />
              </div>
            );
          })}

          {/* Domain B Pins (Below Center Rail) */}
          {trackEventsB.map(({ ev, pos, tier }) => {
            const isHovered = hoveredEventId === ev.id;
            let pinColor = 'bg-[#8c8c8c] border-[#505050]';
            if (ev.type === 'created') {
              pinColor = 'bg-[#c300bb] border-[#f600bb]';
            } else if (ev.type === 'expires') {
              pinColor = 'bg-[#bbc300] border-[#bbc300]';
            }

            return (
              <div
                key={ev.id}
                style={{ left: `${pos}%`, top: '50%' }}
                className={`absolute -translate-x-1/2 flex flex-col items-center pointer-events-none ${
                  isHovered ? 'z-30' : 'z-10'
                }`}
              >
                <div
                  style={{ height: getStemHeight(tier) }}
                  className="w-[1px] bg-[#c300bb]/60 pointer-events-none"
                />
                <div
                  ref={registerTarget(ev.id, 'pin')}
                  className={`pointer-events-auto cursor-pointer w-2.5 h-2.5 border transition-transform ${pinColor} ${
                    isHovered ? 'scale-125 border-[#f0f0f0]' : ''
                  }`}
                />
                <span
                  ref={registerTarget(ev.id, 'badge')}
                  className={`pointer-events-auto cursor-pointer text-[9px] font-mono mt-1 whitespace-nowrap px-1 border transition-colors ${
                    isHovered
                      ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c300bb]'
                      : 'bg-[#0d0d0d]/90 text-[#8c8c8c] border-[#2e2e2e]/60'
                  }`}
                >
                  {getShortTag(ev.type)} {ev.dateStr.slice(0, 10)}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Milestones Table */}
      <div className="border-t border-[#383838]">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="bg-[#141414] border-b border-[#383838] text-[10px] text-[#8c8c8c] uppercase tracking-wider select-none">
                <th className="py-2 px-4 font-semibold min-w-28">Target</th>
                <th className="py-2 px-4 font-semibold w-64">Milestone</th>
                <th className="py-2 px-4 font-semibold w-36">Date (UTC)</th>
                <th className="py-2 px-4 font-semibold w-48">Horizon / Age</th>
                <th className="py-2 px-4 font-semibold">Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2e2e2e]">
              {events.map((ev) => {
                const isHovered = hoveredEventId === ev.id;
                return (
                  <tr
                    key={ev.id}
                    onMouseEnter={() => setHoveredEventId(ev.id)}
                    onMouseLeave={() => setHoveredEventId(null)}
                    className={`transition-colors group ${
                      isHovered ? 'bg-[#1a1a1a]' : 'hover:bg-[#1a1a1a]/80'
                    }`}
                  >
                    <td className="py-2.5 px-4 align-middle whitespace-nowrap">
                      <span className="flex items-center font-bold">
                        <span className={ev.domainKey === 'A' ? 'text-[#c30800]' : 'text-[#c300bb]'}>
                          {ev.domainName}
                        </span>
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-[#f0f0f0] font-semibold">
                      {ev.label}
                    </td>
                    <td className="py-2.5 px-4 text-[#f0f0f0] select-all font-mono">
                      {ev.dateStr}
                    </td>
                    <td className="py-2.5 px-4 text-[#8c8c8c]">
                      {ev.notes || '—'}
                    </td>
                    <td className="py-2.5 px-4 text-[#8c8c8c] text-[11px] truncate max-w-xs">
                      {ev.type === 'created'
                        ? 'Initial ICANN registrar delegation'
                        : ev.type === 'expires'
                        ? 'Registry purge threshold if unrenewed'
                        : 'Authoritative nameserver/RDAP sync'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
