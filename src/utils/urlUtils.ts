// SPDX-License-Identifier: AGPL-3.0-or-later

const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'ed.jp',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.mx', 'org.mx', 'edu.mx', 'gob.mx', 'net.mx',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'nic.in', 'ac.in', 'edu.in', 'gov.in',
  'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg',
  'co.za', 'net.za', 'org.za', 'web.za', 'gov.za',
  'com.tr', 'net.tr', 'org.tr', 'edu.tr', 'gov.tr',
  'com.hk', 'org.hk', 'net.hk', 'edu.hk', 'gov.hk',
  'com.tw', 'org.tw', 'net.tw', 'edu.tw', 'gov.tw',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'gc.ca', 'qc.ca', 'ab.ca', 'bc.ca', 'on.ca',
]);

export function extractApexDomain(hostname: string): string {
  if (!hostname) return '';
  const clean = hostname.toLowerCase().trim().replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(':')) {
    return clean;
  }

  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;

  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}
