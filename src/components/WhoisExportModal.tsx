// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState } from 'react';
import { WhoisDiffResult } from '../types';
import { X, Copy, Check, Download, FileText, Code2, Table } from 'lucide-react';

interface WhoisExportModalProps {
  diff: WhoisDiffResult | null;
  onClose: () => void;
}

export const WhoisExportModal: React.FC<WhoisExportModalProps> = ({ diff, onClose }) => {
  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);

  if (!diff) return null;

  const { domainA, domainB, fieldDiffs, summary } = diff;

  const generateMarkdown = (): string => {
    const lines: string[] = [
      `# WHOIS & OSINT Delta Intelligence Report`,
      `**Target A**: \`${domainA.domainName}\` | **Target B**: \`${domainB.domainName}\``,
      `**Attribution Verdict**: \`${summary.overallAttributionVerdict.replace(/_/g, ' ')}\``,
      `**Generated**: ${new Date(diff.computedAt).toUTCString()}`,
      `**License**: AGPL-3.0-or-later (0xCONFUSED ./whoisnt)`,
      ``,
      `## OSINT Executive Summary`,
      `- **Total OSINT Attributes Compared**: ${summary.totalFieldsCompared}`,
      `- **Divergent Indicators**: ${summary.divergentCount}`,
      `- **Matching Indicators**: ${summary.matchingCount}`,
      `- **Lifecycle Inception Delta**: ${summary.ageDeltaFormatted || 'Comparable'}`,
      `- **Expiration Horizon Delta**: ${summary.expirationDeltaFormatted || 'Comparable'}`,
      `- **BGP Network Alignment**: ${summary.sameAsn ? 'Shared Autonomous System' : 'Separate ASNs'}`,
      `- **Subnet /24 Co-location**: ${summary.sameSubnet24 ? 'Co-located in same /24' : 'Distinct Subnets'}`,
      `- **Shared Nameservers**: ${summary.sharedNameserversCount} / ${summary.totalNameserversCount}`,
      `- **Registrar Alignment**: ${summary.sameRegistrar ? 'Same Registrar' : 'Different Registrars'}`,
      `- **DNS Provider Alignment**: ${summary.sameDnsProvider ? 'Shared DNS Provider' : 'Different Providers'}`,
      `- **Mail Provider Alignment**: ${summary.sameMailProvider ? 'Identical Mail Solution' : 'Different Providers'}`,
      `- **Discovered Shared Linkages**: ${summary.linkages.length > 0 ? summary.linkages.map((l) => l.title).join('; ') : 'None'}`,
      ``,
      `## Structured Comparison Matrix`,
      `| Indicator | Category | Status | ${domainA.domainName} [A] | ${domainB.domainName} [B] | Specification / Notes |`,
      `| :--- | :--- | :---: | :--- | :--- | :--- |`,
    ];

    fieldDiffs.forEach((f) => {
      const valA = Array.isArray(f.valueA) ? f.valueA.join('; ') : String(f.valueA || 'N/A');
      const valB = Array.isArray(f.valueB) ? f.valueB.join('; ') : String(f.valueB || 'N/A');
      lines.push(
        `| **${f.label}** | \`${f.category}\` | \`${f.status}\` | ${valA.replace(/\|/g, '\\|')} | ${valB.replace(/\|/g, '\\|')} | ${f.deltaSummary ? `*${f.deltaSummary}* - ` : ''}${f.rfcOrSpec || ''} |`
      );
    });

    lines.push(``);
    lines.push(`---`);
    lines.push(`*Generated via 0xCONFUSED ./whoisnt — RFC 3912 / RFC 7480 Authoritative Engine*`);

    return lines.join('\n');
  };

  const generateCsv = (): string => {
    const escapeCsv = (str: string) => `"${str.replace(/"/g, '""')}"`;
    const rows = [
      ['Property', 'Category', 'Status', `${domainA.domainName} (Domain A)`, `${domainB.domainName} (Domain B)`, 'Specification', 'Delta Insight'],
      ...fieldDiffs.map((f) => [
        f.label,
        f.category,
        f.status,
        Array.isArray(f.valueA) ? f.valueA.join('; ') : String(f.valueA || ''),
        Array.isArray(f.valueB) ? f.valueB.join('; ') : String(f.valueB || ''),
        f.rfcOrSpec || '',
        f.deltaSummary || '',
      ]),
    ];

    return rows.map((r) => r.map((c) => escapeCsv(String(c))).join(',')).join('\n');
  };

  const handleDownload = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopy = (content: string, format: string) => {
    try {
      navigator.clipboard.writeText(content);
      setCopiedFormat(format);
      setTimeout(() => setCopiedFormat(null), 2000);
    } catch {}
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl bg-[#141414] border border-[#383838] shadow-2xl relative flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="h-[2px] w-full bg-gradient-to-r from-[#c30800] via-[#c300bb] to-[#bbc300]" />

        {/* Modal Header */}
        <div className="p-4 border-b border-[#2e2e2e] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Download className="w-4 h-4 text-[#c30800]" />
            <h3 className="font-mono text-sm font-bold text-[#f0f0f0] uppercase tracking-wider">
              Export WHOIS Diff Intelligence
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 text-[#8c8c8c] hover:text-[#f0f0f0] transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 flex flex-col gap-4">
          <div className="bg-[#0d0d0d] border border-[#2e2e2e] p-3 text-xs font-mono text-[#8c8c8c] flex items-center justify-between">
            <div>
              <span className="text-[#f0f0f0] font-bold">{domainA.domainName}</span>
              <span className="text-[#737373] mx-2">vs</span>
              <span className="text-[#f0f0f0] font-bold">{domainB.domainName}</span>
            </div>
            <span>{fieldDiffs.length} attributes compared</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Markdown */}
            <div className="bg-[#1a1a1a] border border-[#2e2e2e] p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#f0f0f0] mb-1">
                  <FileText className="w-4 h-4 text-[#c30800]" />
                  <span>MARKDOWN</span>
                </div>
                <p className="text-[11px] text-[#8c8c8c]">
                  Formatted markdown report with executive summary and structured delta table.
                </p>
              </div>

              <div className="mt-4 flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() =>
                    handleDownload(
                      generateMarkdown(),
                      `whois-diff-${domainA.domainName}-vs-${domainB.domainName}.md`,
                      'text/markdown'
                    )
                  }
                  className="w-full py-1.5 px-2 bg-[#141414] hover:bg-[#262626] border border-[#383838] hover:border-[#c30800] text-xs font-mono font-bold text-[#f0f0f0] transition-colors cursor-pointer"
                >
                  DOWNLOAD .MD
                </button>
                <button
                  type="button"
                  onClick={() => handleCopy(generateMarkdown(), 'md')}
                  className="w-full py-1.5 px-2 bg-[#0d0d0d] hover:bg-[#141414] border border-[#2e2e2e] text-[11px] font-mono text-[#8c8c8c] hover:text-[#f0f0f0] flex items-center justify-center gap-1 transition-colors cursor-pointer"
                >
                  {copiedFormat === 'md' ? <Check className="w-3 h-3 text-[#bbc300]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedFormat === 'md' ? 'COPIED' : 'COPY'}</span>
                </button>
              </div>
            </div>

            {/* JSON */}
            <div className="bg-[#1a1a1a] border border-[#2e2e2e] p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#f0f0f0] mb-1">
                  <Code2 className="w-4 h-4 text-[#c300bb]" />
                  <span>RAW JSON</span>
                </div>
                <p className="text-[11px] text-[#8c8c8c]">
                  Complete machine-readable JSON structure including raw WHOIS buffers and diff metrics.
                </p>
              </div>

              <div className="mt-4 flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() =>
                    handleDownload(
                      JSON.stringify(diff, null, 2),
                      `whois-diff-${domainA.domainName}-vs-${domainB.domainName}.json`,
                      'application/json'
                    )
                  }
                  className="w-full py-1.5 px-2 bg-[#141414] hover:bg-[#262626] border border-[#383838] hover:border-[#c300bb] text-xs font-mono font-bold text-[#f0f0f0] transition-colors cursor-pointer"
                >
                  DOWNLOAD .JSON
                </button>
                <button
                  type="button"
                  onClick={() => handleCopy(JSON.stringify(diff, null, 2), 'json')}
                  className="w-full py-1.5 px-2 bg-[#0d0d0d] hover:bg-[#141414] border border-[#2e2e2e] text-[11px] font-mono text-[#8c8c8c] hover:text-[#f0f0f0] flex items-center justify-center gap-1 transition-colors cursor-pointer"
                >
                  {copiedFormat === 'json' ? <Check className="w-3 h-3 text-[#bbc300]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedFormat === 'json' ? 'COPIED' : 'COPY'}</span>
                </button>
              </div>
            </div>

            {/* CSV */}
            <div className="bg-[#1a1a1a] border border-[#2e2e2e] p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#f0f0f0] mb-1">
                  <Table className="w-4 h-4 text-[#bbc300]" />
                  <span>CSV MATRIX</span>
                </div>
                <p className="text-[11px] text-[#8c8c8c]">
                  Tabular CSV spreadsheet export compatible with Excel, Sheets, and SIEM import tools.
                </p>
              </div>

              <div className="mt-4 flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() =>
                    handleDownload(
                      generateCsv(),
                      `whois-diff-${domainA.domainName}-vs-${domainB.domainName}.csv`,
                      'text/csv'
                    )
                  }
                  className="w-full py-1.5 px-2 bg-[#141414] hover:bg-[#262626] border border-[#383838] hover:border-[#bbc300] text-xs font-mono font-bold text-[#f0f0f0] transition-colors cursor-pointer"
                >
                  DOWNLOAD .CSV
                </button>
                <button
                  type="button"
                  onClick={() => handleCopy(generateCsv(), 'csv')}
                  className="w-full py-1.5 px-2 bg-[#0d0d0d] hover:bg-[#141414] border border-[#2e2e2e] text-[11px] font-mono text-[#8c8c8c] hover:text-[#f0f0f0] flex items-center justify-center gap-1 transition-colors cursor-pointer"
                >
                  {copiedFormat === 'csv' ? <Check className="w-3 h-3 text-[#bbc300]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedFormat === 'csv' ? 'COPIED' : 'COPY'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#0d0d0d] border-t border-[#2e2e2e] flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 bg-[#141414] hover:bg-[#262626] border border-[#383838] text-xs font-mono text-[#f0f0f0] transition-colors cursor-pointer"
          >
            CLOSE
          </button>
        </div>
      </div>
    </div>
  );
};
