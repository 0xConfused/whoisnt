// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { WhoisDiffResult } from '../types';

interface OsintTopologyMapProps {
  diff: WhoisDiffResult;
}

interface TopologyNode {
  id: string;
  label: string;
  sublabel: string;
  type: 'domainA' | 'domainB' | 'shared' | 'uniqueA' | 'uniqueB';
  category: 'core' | 'network' | 'dns' | 'mail' | 'cert' | 'registrar' | 'token';
  x: number;
  y: number;
}

interface TopologyLink {
  from: string;
  to: string;
  isShared: boolean;
  label?: string;
}

const CANVAS_WIDTH = 1120;
const NODE_WIDTH = 164;
const NODE_HEIGHT = 66;
const ROW_GAP = 18;
const ROW_STEP = NODE_HEIGHT + ROW_GAP;
const TOP_PAD = 36;

const COL_X = {
  uniqueA: 16,
  domainA: 247,
  shared: 478,
  domainB: 709,
  uniqueB: 940,
} as const;

export const OsintTopologyMap: React.FC<OsintTopologyMapProps> = ({ diff }) => {
  const { domainA, domainB, summary } = diff;

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<'all' | 'shared' | 'network' | 'dns'>('all');
  const [view, setView] = useState<{ zoom: number; x: number; y: number }>({ zoom: 1, x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);

  const viewportRef = useRef<HTMLDivElement | null>(null);
  const canvasHeightRef = useRef<number>(300);
  const hasInteractedRef = useRef<boolean>(false);
  const suppressClickRef = useRef<boolean>(false);
  const dragRef = useRef<{
    active: boolean;
    startX: number;
    startY: number;
    lastX: number;
    lastY: number;
    moved: boolean;
  }>({ active: false, startX: 0, startY: 0, lastX: 0, lastY: 0, moved: false });

  // Compute unpositioned nodes and links first, then assign clean non-overlapping coordinates
  const { nodes, links, canvasHeight } = useMemo(() => {
    type RawNode = Omit<TopologyNode, 'x' | 'y'>;
    const rawNodes: RawNode[] = [];
    const linkList: TopologyLink[] = [];

    // Core Domain Nodes
    rawNodes.push({
      id: 'domA',
      label: domainA.domainName,
      sublabel: domainA.source.toUpperCase(),
      type: 'domainA',
      category: 'core',
    });

    rawNodes.push({
      id: 'domB',
      label: domainB.domainName,
      sublabel: domainB.source.toUpperCase(),
      type: 'domainB',
      category: 'core',
    });

    // CENTER HUBS: Shared Infrastructure
    if (summary.sameAsn && domainA.asn) {
      const id = 'shared_asn';
      rawNodes.push({
        id,
        label: domainA.asn,
        sublabel: domainA.asnName || 'SHARED BGP ASN',
        type: 'shared',
        category: 'network',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'BGP' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'BGP' });
    }

    if (summary.sameSubnet24 && domainA.subnet24) {
      const id = 'shared_subnet';
      rawNodes.push({
        id,
        label: domainA.subnet24,
        sublabel: 'CO-LOCATED /24',
        type: 'shared',
        category: 'network',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: '/24' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: '/24' });
    }

    const setNsB = new Set(domainB.nameservers.map((s) => s.toLowerCase()));
    const sharedNsList = domainA.nameservers.filter((s) => setNsB.has(s.toLowerCase()));
    if (sharedNsList.length > 0) {
      const id = 'shared_ns';
      rawNodes.push({
        id,
        label: `${sharedNsList.length} Shared NS`,
        sublabel: sharedNsList[0],
        type: 'shared',
        category: 'dns',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'DNS' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'DNS' });
    }

    if (summary.sameMailProvider && domainA.mailProvider && domainA.mailProvider !== 'No MX Records Listed') {
      const id = 'shared_mail';
      rawNodes.push({
        id,
        label: domainA.mailProvider.split('(')[0].trim(),
        sublabel: 'SHARED MAIL MX',
        type: 'shared',
        category: 'mail',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'MX' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'MX' });
    }

    if (summary.sharedVerificationTokensCount > 0) {
      const id = 'shared_tokens';
      rawNodes.push({
        id,
        label: `${summary.sharedVerificationTokensCount} IDP Tokens`,
        sublabel: 'SHARED TXT PROOF',
        type: 'shared',
        category: 'token',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'TXT' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'TXT' });
    }

    if (summary.sameTlsSubjectOrg && domainA.tlsSubjectOrg) {
      const id = 'shared_tls_org';
      rawNodes.push({
        id,
        label: domainA.tlsSubjectOrg,
        sublabel: 'SSL SUBJECT ORG',
        type: 'shared',
        category: 'cert',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'TLS' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'TLS' });
    }

    if (summary.sharedPtrHostnames && summary.sharedPtrHostnames.length > 0) {
      const id = 'shared_ptr';
      rawNodes.push({
        id,
        label: summary.sharedPtrHostnames[0],
        sublabel: 'SHARED PTR HOSTNAME',
        type: 'shared',
        category: 'network',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'PTR' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'PTR' });
    }

    if (summary.sharedSpfIps && summary.sharedSpfIps.length > 0) {
      const id = 'shared_spf_ip';
      rawNodes.push({
        id,
        label: summary.sharedSpfIps[0],
        sublabel: 'SHARED SPF ORIGIN IP',
        type: 'shared',
        category: 'network',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'SPF' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'SPF' });
    }

    if (summary.sameSoaRname && domainA.soaRname) {
      const id = 'shared_soa_rname';
      rawNodes.push({
        id,
        label: domainA.soaRname,
        sublabel: 'SHARED SOA RNAME',
        type: 'shared',
        category: 'dns',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'SOA' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'SOA' });
    }

    if ((summary.sameDmarcRua || summary.sameDmarcRuf) && (domainA.dmarcRuf || domainA.dmarcRua)) {
      const id = 'shared_dmarc';
      rawNodes.push({
        id,
        label: domainA.dmarcRuf || domainA.dmarcRua || '',
        sublabel: 'SHARED DMARC REPORT',
        type: 'shared',
        category: 'mail',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'DMARC' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'DMARC' });
    }

    if (summary.sharedDkimTargets && summary.sharedDkimTargets.length > 0) {
      const id = 'shared_dkim';
      rawNodes.push({
        id,
        label: summary.sharedDkimTargets[0],
        sublabel: 'SHARED DKIM TENANT',
        type: 'shared',
        category: 'mail',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'DKIM' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'DKIM' });
    }

    const isRedactedRegA = !domainA.registrar || domainA.registrar === 'Protected / Redacted';
    const isSharedRegistrar = summary.sameRegistrar && !isRedactedRegA;

    if (isSharedRegistrar) {
      const id = 'shared_registrar';
      rawNodes.push({
        id,
        label: domainA.registrar,
        sublabel: 'SHARED REGISTRAR',
        type: 'shared',
        category: 'registrar',
      });
      linkList.push({ from: 'domA', to: id, isShared: true, label: 'REG' });
      linkList.push({ from: 'domB', to: id, isShared: true, label: 'REG' });
    }

    // FLANKING NODES: Domain A Unique (Left Column)
    if (!summary.sameAsn && domainA.asn) {
      const id = 'asn_a';
      rawNodes.push({
        id,
        label: domainA.asn,
        sublabel: domainA.asnName || 'UPSTREAM ASN',
        type: 'uniqueA',
        category: 'network',
      });
      linkList.push({ from: 'domA', to: id, isShared: false, label: 'BGP' });
    }

    if (!isSharedRegistrar && domainA.registrar) {
      const idRegA = 'reg_a';
      rawNodes.push({
        id: idRegA,
        label: domainA.registrar,
        sublabel: 'REGISTRAR',
        type: 'uniqueA',
        category: 'registrar',
      });
      linkList.push({ from: 'domA', to: idRegA, isShared: false, label: 'REG' });
    }

    const sharedNsLower = new Set(sharedNsList.map((s) => s.toLowerCase()));
    if (domainA.nameservers.length > 0 && !sharedNsLower.has(domainA.nameservers[0].toLowerCase())) {
      const idNsA = 'ns_a';
      rawNodes.push({
        id: idNsA,
        label: domainA.nameservers[0],
        sublabel: domainA.dnsProvider || 'DNS CLUSTER',
        type: 'uniqueA',
        category: 'dns',
      });
      linkList.push({ from: 'domA', to: idNsA, isShared: false, label: 'DNS' });
    }

    if (!summary.sameMailProvider && domainA.mailProvider && domainA.mailProvider !== 'No MX Records Listed') {
      const idMailA = 'mail_a';
      rawNodes.push({
        id: idMailA,
        label: domainA.mailProvider.split('(')[0].trim(),
        sublabel: 'MAIL GATEWAY',
        type: 'uniqueA',
        category: 'mail',
      });
      linkList.push({ from: 'domA', to: idMailA, isShared: false, label: 'MX' });
    }

    // FLANKING NODES: Domain B Unique (Right Column)
    if (!summary.sameAsn && domainB.asn) {
      const id = 'asn_b';
      rawNodes.push({
        id,
        label: domainB.asn,
        sublabel: domainB.asnName || 'UPSTREAM ASN',
        type: 'uniqueB',
        category: 'network',
      });
      linkList.push({ from: 'domB', to: id, isShared: false, label: 'BGP' });
    }

    if (!isSharedRegistrar && domainB.registrar) {
      const idRegB = 'reg_b';
      rawNodes.push({
        id: idRegB,
        label: domainB.registrar,
        sublabel: 'REGISTRAR',
        type: 'uniqueB',
        category: 'registrar',
      });
      linkList.push({ from: 'domB', to: idRegB, isShared: false, label: 'REG' });
    }

    if (domainB.nameservers.length > 0 && !sharedNsLower.has(domainB.nameservers[0].toLowerCase())) {
      const idNsB = 'ns_b';
      rawNodes.push({
        id: idNsB,
        label: domainB.nameservers[0],
        sublabel: domainB.dnsProvider || 'DNS CLUSTER',
        type: 'uniqueB',
        category: 'dns',
      });
      linkList.push({ from: 'domB', to: idNsB, isShared: false, label: 'DNS' });
    }

    if (!summary.sameMailProvider && domainB.mailProvider && domainB.mailProvider !== 'No MX Records Listed') {
      const idMailB = 'mail_b';
      rawNodes.push({
        id: idMailB,
        label: domainB.mailProvider.split('(')[0].trim(),
        sublabel: 'MAIL GATEWAY',
        type: 'uniqueB',
        category: 'mail',
      });
      linkList.push({ from: 'domB', to: idMailB, isShared: false, label: 'MX' });
    }

    // Filter active nodes first so columns pack and center cleanly per filter
    const visibleRaw = rawNodes.filter((n) => {
      if (activeFilter === 'all') return true;
      if (activeFilter === 'shared') return n.type === 'shared' || n.type === 'domainA' || n.type === 'domainB';
      if (activeFilter === 'network') return n.category === 'network' || n.type === 'domainA' || n.type === 'domainB';
      if (activeFilter === 'dns') return n.category === 'dns' || n.type === 'domainA' || n.type === 'domainB';
      return true;
    });

    const colUniqueA = visibleRaw.filter((n) => n.type === 'uniqueA');
    const colShared = visibleRaw.filter((n) => n.type === 'shared');
    const colUniqueB = visibleRaw.filter((n) => n.type === 'uniqueB');
    const colDomA = visibleRaw.filter((n) => n.type === 'domainA');
    const colDomB = visibleRaw.filter((n) => n.type === 'domainB');

    const maxColCount = Math.max(1, colUniqueA.length, colShared.length, colUniqueB.length);
    const computedHeight = Math.max(300, TOP_PAD * 2 + maxColCount * NODE_HEIGHT + (maxColCount - 1) * ROW_GAP);

    const placeColumn = (items: RawNode[], x: number): TopologyNode[] => {
      if (items.length === 0) return [];
      const colHeight = items.length * NODE_HEIGHT + (items.length - 1) * ROW_GAP;
      const startY = Math.round((computedHeight - colHeight) / 2);
      return items.map((item, idx) => ({
        ...item,
        x,
        y: startY + idx * ROW_STEP,
      }));
    };

    const positionedNodes: TopologyNode[] = [
      ...placeColumn(colUniqueA, COL_X.uniqueA),
      ...placeColumn(colDomA, COL_X.domainA),
      ...placeColumn(colShared, COL_X.shared),
      ...placeColumn(colDomB, COL_X.domainB),
      ...placeColumn(colUniqueB, COL_X.uniqueB),
    ];

    return {
      nodes: positionedNodes,
      links: linkList,
      canvasHeight: computedHeight,
    };
  }, [domainA, domainB, summary, activeFilter]);

  const selectedNode = useMemo(() => {
    return nodes.find((n) => n.id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  const nodeMap = useMemo(() => {
    const map = new Map<string, TopologyNode>();
    nodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [nodes]);

  const hasSharedVisible = useMemo(() => nodes.some((n) => n.type === 'shared'), [nodes]);

  const viewportHeight = Math.max(360, canvasHeight + 48);
  canvasHeightRef.current = canvasHeight;

  const clampView = useCallback((nextX: number, nextY: number, nextZoom: number) => {
    const el = viewportRef.current;
    const clampedZoom = Math.min(2.2, Math.max(0.4, nextZoom));
    if (!el) return { zoom: clampedZoom, x: nextX, y: nextY };

    const vpWidth = el.clientWidth;
    const vpHeight = el.clientHeight;
    const scaledW = CANVAS_WIDTH * clampedZoom;
    const scaledH = canvasHeightRef.current * clampedZoom;

    const minX = Math.min(0, vpWidth - scaledW);
    const maxX = Math.max(0, vpWidth - scaledW);
    const minY = Math.min(0, vpHeight - scaledH);
    const maxY = Math.max(0, vpHeight - scaledH);

    return {
      zoom: clampedZoom,
      x: Math.min(maxX, Math.max(minX, nextX)),
      y: Math.min(maxY, Math.max(minY, nextY)),
    };
  }, []);

  const centerView = useCallback(() => {
    const el = viewportRef.current;
    if (!el) return;
    const width = el.clientWidth;
    const height = el.clientHeight || viewportHeight;
    const fitZoom =
      width > 0 && width < CANVAS_WIDTH + 32
        ? Math.max(0.5, +((width - 32) / CANVAS_WIDTH).toFixed(2))
        : 1;
    const x = Math.round((width - CANVAS_WIDTH * fitZoom) / 2);
    const y = Math.round((height - canvasHeight * fitZoom) / 2);
    setView(clampView(x, y, fitZoom));
  }, [canvasHeight, viewportHeight, clampView]);

  useEffect(() => {
    hasInteractedRef.current = false;
    centerView();
  }, [domainA.domainName, domainB.domainName, activeFilter, centerView]);

  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;
    const observer = new ResizeObserver(() => {
      if (!hasInteractedRef.current) {
        centerView();
      } else {
        setView((prev) => clampView(prev.x, prev.y, prev.zoom));
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [centerView, clampView]);

  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      hasInteractedRef.current = true;
      const rect = el.getBoundingClientRect();
      const cursorX = e.clientX - rect.left;
      const cursorY = e.clientY - rect.top;
      const delta = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
      const zoomFactor = Math.exp(-delta * 0.0015);

      setView((prev) => {
        const nextZoom = Math.min(2.2, Math.max(0.4, +(prev.zoom * zoomFactor).toFixed(3)));
        const ratio = nextZoom / prev.zoom;
        const nextX = cursorX - (cursorX - prev.x) * ratio;
        const nextY = cursorY - (cursorY - prev.y) * ratio;
        return clampView(nextX, nextY, nextZoom);
      });
    };

    el.addEventListener('wheel', handleWheel, { passive: false });
    return () => el.removeEventListener('wheel', handleWheel);
  }, [clampView]);

  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      if (!dragRef.current.active) return;
      const totalDx = e.clientX - dragRef.current.startX;
      const totalDy = e.clientY - dragRef.current.startY;
      const stepX = e.clientX - dragRef.current.lastX;
      const stepY = e.clientY - dragRef.current.lastY;
      dragRef.current.lastX = e.clientX;
      dragRef.current.lastY = e.clientY;

      if (!dragRef.current.moved && Math.hypot(totalDx, totalDy) > 4) {
        dragRef.current.moved = true;
        suppressClickRef.current = true;
        hasInteractedRef.current = true;
      }
      if (dragRef.current.moved) {
        setView((prev) => clampView(prev.x + stepX, prev.y + stepY, prev.zoom));
      }
    };

    const handlePointerUp = () => {
      if (!dragRef.current.active) return;
      dragRef.current.active = false;
      setIsDragging(false);
    };

    window.addEventListener('pointermove', handlePointerMove);
    window.addEventListener('pointerup', handlePointerUp);
    window.addEventListener('pointercancel', handlePointerUp);
    return () => {
      window.removeEventListener('pointermove', handlePointerMove);
      window.removeEventListener('pointerup', handlePointerUp);
      window.removeEventListener('pointercancel', handlePointerUp);
    };
  }, [clampView]);

  const handleViewportPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    suppressClickRef.current = false;
    dragRef.current = {
      active: true,
      startX: e.clientX,
      startY: e.clientY,
      lastX: e.clientX,
      lastY: e.clientY,
      moved: false,
    };
    setIsDragging(true);
  };

  const handleResetView = () => {
    hasInteractedRef.current = false;
    centerView();
  };

  const handleNodeClick = (node: TopologyNode) => {
    if (suppressClickRef.current) {
      suppressClickRef.current = false;
      return;
    }
    setSelectedNodeId((prev) => (prev === node.id ? null : node.id));
  };

  return (
    <div id="infrastructure-topology-map" className="bg-[#141414] border border-[#383838] rounded-none overflow-hidden flex flex-col relative mb-6">
      <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

      {/* Minimal Control & Legend Toolbar */}
      <div className="px-4 py-2.5 bg-[#141414] flex flex-wrap items-center justify-between gap-3 border-b border-[#383838]">
        <div className="flex flex-wrap items-center gap-1.5">
          {[
            { id: 'all', label: 'All Nodes' },
            { id: 'shared', label: 'Shared Hubs' },
            { id: 'network', label: 'BGP / Network' },
            { id: 'dns', label: 'DNS / Nameservers' },
          ].map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setActiveFilter(f.id as 'all' | 'shared' | 'network' | 'dns')}
              className={`px-2 py-1 text-[10px] rounded-none border font-mono uppercase tracking-wider cursor-pointer transition-colors font-semibold shrink-0 ${
                activeFilter === f.id
                  ? 'bg-[#1a1a1a] text-[#f0f0f0] border-[#c30800]'
                  : 'bg-[#0d0d0d] text-[#8c8c8c] border-[#2e2e2e] hover:text-[#f0f0f0] hover:border-[#383838]'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={handleResetView}
            className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider border border-[#383838] bg-[#141414] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors rounded-none cursor-pointer font-semibold"
            title="Reset topology view"
          >
            RESET VIEW
          </button>
        </div>
      </div>

      {/* Interactive Pan & Zoom Canvas Viewport */}
      <div
        ref={viewportRef}
        onPointerDown={handleViewportPointerDown}
        onDoubleClick={handleResetView}
        style={{ height: `${viewportHeight}px` }}
        className={`bg-[#0d0d0d] overflow-hidden relative select-none touch-none ${
          isDragging ? 'cursor-grabbing' : 'cursor-grab'
        }`}
      >
        <div
          style={{
            width: `${CANVAS_WIDTH}px`,
            height: `${canvasHeight}px`,
            transform: `translate(${view.x}px, ${view.y}px) scale(${view.zoom})`,
            transformOrigin: '0 0',
          }}
          className="relative"
        >
            {/* Subtle Column Headers */}
            <div className="absolute top-2 left-0 right-0 pointer-events-none select-none font-mono text-[9px] uppercase tracking-wider text-[#737373]">
              <span style={{ position: 'absolute', left: `${COL_X.uniqueA}px`, width: `${NODE_WIDTH}px` }} className="text-center truncate">
                Domain A Exclusive
              </span>
              <span style={{ position: 'absolute', left: `${COL_X.domainA}px`, width: `${NODE_WIDTH}px` }} className="text-center truncate text-[#c30800]">
                Base Target
              </span>
              <span style={{ position: 'absolute', left: `${COL_X.shared}px`, width: `${NODE_WIDTH}px` }} className="text-center truncate text-[#bbc300]">
                Shared Hubs
              </span>
              <span style={{ position: 'absolute', left: `${COL_X.domainB}px`, width: `${NODE_WIDTH}px` }} className="text-center truncate text-[#c300bb]">
                Comparison Target
              </span>
              <span style={{ position: 'absolute', left: `${COL_X.uniqueB}px`, width: `${NODE_WIDTH}px` }} className="text-center truncate">
                Domain B Exclusive
              </span>
            </div>

            <svg
              width={CANVAS_WIDTH}
              height={canvasHeight}
              viewBox={`0 0 ${CANVAS_WIDTH} ${canvasHeight}`}
              className="absolute inset-0 pointer-events-none"
            >
              {/* Edge-to-Edge Cubic Bezier Links */}
              {links.map((link, idx) => {
                const fromNode = nodeMap.get(link.from);
                const toNode = nodeMap.get(link.to);
                if (!fromNode || !toNode) return null;

                const isSelected = selectedNodeId === link.from || selectedNodeId === link.to;
                const goRight = toNode.x > fromNode.x;

                const x1 = goRight ? fromNode.x + NODE_WIDTH : fromNode.x;
                const y1 = fromNode.y + NODE_HEIGHT / 2;
                const x2 = goRight ? toNode.x : toNode.x + NODE_WIDTH;
                const y2 = toNode.y + NODE_HEIGHT / 2;
                const cx = (x1 + x2) / 2;
                const my = (y1 + y2) / 2;

                const pathD = `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`;
                const strokeColor = link.isShared
                  ? isSelected
                    ? '#bbc300'
                    : '#c36a00'
                  : link.from === 'domA'
                  ? '#c30800'
                  : '#c300bb';

                return (
                  <g key={idx}>
                    <path
                      d={pathD}
                      fill="none"
                      stroke={strokeColor}
                      strokeWidth={isSelected ? 2 : link.isShared ? 1.5 : 1.25}
                      strokeDasharray={link.isShared ? 'none' : '4 3'}
                      strokeOpacity={isSelected ? 1 : link.isShared ? 0.8 : 0.55}
                    />
                    <rect x={x1 - 2} y={y1 - 2} width={4} height={4} fill={strokeColor} />
                    <rect x={x2 - 2} y={y2 - 2} width={4} height={4} fill={strokeColor} />
                    {link.label && (
                      <g>
                        <rect
                          x={cx - 18}
                          y={my - 7}
                          width={36}
                          height={14}
                          fill="#0d0d0d"
                        />
                        <text
                          x={cx}
                          y={my + 3}
                          fill={isSelected ? '#f0f0f0' : '#8c8c8c'}
                          fontSize="8.5"
                          fontFamily="Fira Code, monospace"
                          textAnchor="middle"
                          className="select-none"
                        >
                          {link.label}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}
            </svg>

            {/* Empty Shared Column Indicator */}
            {!hasSharedVisible && (
              <div
                style={{
                  position: 'absolute',
                  left: `${COL_X.shared}px`,
                  top: `${Math.round((canvasHeight - NODE_HEIGHT) / 2)}px`,
                  width: `${NODE_WIDTH}px`,
                  height: `${NODE_HEIGHT}px`,
                }}
                className="border border-dashed border-[#2e2e2e] bg-[#111111] flex flex-col items-center justify-center px-2 text-center select-none z-10"
              >
                <span className="font-mono text-[10px] font-bold text-[#737373] uppercase">
                  No Shared Nodes
                </span>
                <span className="font-mono text-[9px] text-[#737373]/80 mt-0.5">
                  Isolated infra
                </span>
              </div>
            )}

            {/* Render Nodes */}
            {nodes.map((node) => {
              const getNodeKindLabel = (n: TopologyNode): string => {
                if (n.category === 'core') return 'DOMAIN';
                if (n.category === 'registrar') return 'REGISTRAR';
                if (n.category === 'cert') return 'TLS CERTIFICATE';
                if (n.category === 'token') return 'TXT VERIFICATION';
                if (n.id === 'shared_subnet') return 'IP SUBNET /24';
                if (n.id === 'shared_ptr') return 'PTR HOSTNAME';
                if (n.id === 'shared_spf_ip') return 'SPF ORIGIN IP';
                if (n.category === 'network') return 'BGP ASN';
                if (n.id === 'shared_soa_rname') return 'SOA CONTACT';
                if (n.category === 'dns') return 'NAMESERVER';
                if (n.id === 'shared_dmarc') return 'DMARC REPORT';
                if (n.id === 'shared_dkim') return 'DKIM TENANT';
                if (n.category === 'mail') return 'MAIL PROVIDER';
                return 'INDICATOR';
              };

              const kindLabel = getNodeKindLabel(node);
              const REDUNDANT_SUBLABELS = new Set([
                'REGISTRAR',
                'SHARED REGISTRAR',
                'SHARED BGP ASN',
                'UPSTREAM ASN',
                'CO-LOCATED /24',
                'SHARED MAIL MX',
                'MAIL GATEWAY',
                'SHARED TXT PROOF',
                'SSL SUBJECT ORG',
                'SHARED PTR HOSTNAME',
                'SHARED SPF ORIGIN IP',
                'SHARED SOA RNAME',
                'SHARED DMARC REPORT',
                'SHARED DKIM TENANT',
                'DNS CLUSTER',
              ]);
              const normSub = node.sublabel.trim().toUpperCase();
              const normKind = kindLabel.trim().toUpperCase();
              const normLabel = node.label.trim().toUpperCase();
              const showSublabel =
                Boolean(normSub) &&
                normSub !== normKind &&
                normSub.replace(/^SHARED\s+/, '') !== normKind &&
                normSub !== normLabel &&
                !REDUNDANT_SUBLABELS.has(normSub);

              const isSelected = selectedNodeId === node.id;
              let borderClass = 'border-[#383838]';
              let bgClass = 'bg-[#141414]';
              let tagColor = 'text-[#8c8c8c]';

              if (node.type === 'domainA') {
                borderClass = isSelected ? 'border-[#f60a00] ring-1 ring-[#f60a00]' : 'border-[#c30800]';
                bgClass = 'bg-[#1a1414]';
                tagColor = 'text-[#c30800]';
              } else if (node.type === 'domainB') {
                borderClass = isSelected ? 'border-[#f600bb] ring-1 ring-[#f600bb]' : 'border-[#c300bb]';
                bgClass = 'bg-[#181418]';
                tagColor = 'text-[#c300bb]';
              } else if (node.type === 'shared') {
                borderClass = isSelected ? 'border-[#bbc300] ring-1 ring-[#bbc300]' : 'border-[#c36a00]';
                bgClass = 'bg-[#181612]';
                tagColor = 'text-[#bbc300]';
              } else if (node.type === 'uniqueA') {
                borderClass = isSelected ? 'border-[#c30800] ring-1 ring-[#c30800]' : 'border-[#c30800]/50';
                tagColor = 'text-[#c30800]';
              } else if (node.type === 'uniqueB') {
                borderClass = isSelected ? 'border-[#c300bb] ring-1 ring-[#c300bb]' : 'border-[#c300bb]/50';
                tagColor = 'text-[#c300bb]';
              }

              return (
                <div
                  key={node.id}
                  onClick={() => handleNodeClick(node)}
                  style={{
                    position: 'absolute',
                    left: `${node.x}px`,
                    top: `${node.y}px`,
                    width: `${NODE_WIDTH}px`,
                    height: `${NODE_HEIGHT}px`,
                  }}
                  className={`p-2 border ${borderClass} ${bgClass} cursor-pointer transition-colors hover:border-[#f0f0f0]/60 z-10 flex flex-col justify-center`}
                >
                  <div className="flex items-center justify-between gap-1 mb-0.5">
                    <span className={`text-[9px] font-mono uppercase tracking-wider font-bold truncate ${tagColor}`}>
                      {kindLabel}
                    </span>
                  </div>

                  <div className="font-mono text-xs font-bold text-[#f0f0f0] truncate" title={node.label}>
                    {node.label}
                  </div>

                  {showSublabel && (
                    <div className="text-[10px] font-mono text-[#8c8c8c] truncate mt-0.5" title={node.sublabel}>
                      {node.sublabel}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

      {/* Selected Node Details Drawer Bar */}
      {selectedNode && (
        <div className="p-3 bg-[#111111] border-t border-[#383838] flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#8c8c8c]">SELECTED NODE:</span>
            <strong className="text-[#f0f0f0]">{selectedNode.label}</strong>
            <span className="text-[#737373]">[{selectedNode.sublabel}]</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setSelectedNodeId(null)}
              className="text-[#737373] hover:text-[#f0f0f0] px-2 py-1"
            >
              DESELECT
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
