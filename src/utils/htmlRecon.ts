// SPDX-License-Identifier: AGPL-3.0-or-later

import { VerificationTokenItem } from '../types';
import { extractApexDomain } from './urlUtils';

/**
 * Static, zero-execution HTML, Header, Resource, DOM, Analytics ID, and Technology analyzer.
 * Runs identically in Node.js (server.ts) and Browser (DOMParser inert mode).
 * Security guarantee:
 *  - NEVER calls eval(), Function(), innerHTML, document.write(), or injects scripts/tags.
 *  - In the browser, parses HTML exclusively with DOMParser().parseFromString(html, 'text/html'),
 *    which does not execute scripts, fire event handlers, or load external subresources.
 *  - Strips all cookie/auth/session headers using an explicit safe header allowlist.
 */

export const MAX_HTML_RECON_BYTES = 512 * 1024;
export const MAX_SCRIPT_TEXT_BYTES = 192 * 1024;

const ALLOWED_RESPONSE_HEADERS = new Set([
  'cache-control',
  'cf-cache-status',
  'cf-ray',
  'content-security-policy',
  'content-type',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'link',
  'nel',
  'permissions-policy',
  'referrer-policy',
  'server',
  'strict-transport-security',
  'via',
  'x-amz-cf-id',
  'x-amz-cf-pop',
  'x-cache',
  'x-content-type-options',
  'x-drupal-cache',
  'x-frame-options',
  'x-generator',
  'x-github-request-id',
  'x-nextjs-cache',
  'x-powered-by',
  'x-robots-tag',
  'x-served-by',
  'x-shopify-stage',
  'x-vercel-cache',
  'x-vercel-id',
  'x-wix-request-id',
]);

export interface StaticHtmlReconResult {
  httpHeaderSummary: string[];
  cspExternalDomains: string[];
  htmlTitle?: string;
  htmlDescription?: string;
  htmlGenerator?: string;
  htmlAuthor?: string;
  htmlRobots?: string;
  canonicalUrl?: string;
  openGraphSiteName?: string;
  twitterSite?: string;
  htmlVerificationTokens: VerificationTokenItem[];
  domMarkers: string[];
  domStats: string;
  scriptUrls: string[];
  resourceSummary: string[];
  analyticsIds: string[];
  footerCopyrights: string[];
  copyrightEntities: string[];
  technologies: string[];
  externalDomains: string[];
}

export function sanitizeHttpHeaders(headersInput: Headers | Record<string, string | undefined>): Record<string, string> {
  const sanitized: Record<string, string> = {};
  const entries: Array<[string, string]> = [];

  if (typeof Headers !== 'undefined' && headersInput instanceof Headers) {
    headersInput.forEach((value, key) => {
      entries.push([key, value]);
    });
  } else if (headersInput && typeof headersInput === 'object') {
    for (const [k, v] of Object.entries(headersInput)) {
      if (typeof v === 'string') entries.push([k, v]);
    }
  }

  for (const [rawKey, rawVal] of entries) {
    const key = rawKey.trim().toLowerCase();
    if (!ALLOWED_RESPONSE_HEADERS.has(key)) continue;
    // Strip control chars and allow larger CSP/Link headers for directive parsing while bounding payload size
    const limit = key === 'content-security-policy' ? 4096 : 600;
    const cleanVal = String(rawVal).replace(/[\r\n\0]+/g, ' ').trim().slice(0, limit);
    if (cleanVal) {
      sanitized[key] = cleanVal;
    }
  }

  return sanitized;
}

function extractCspExternalDomains(cspValue: string | undefined, targetDomain: string): string[] {
  if (!cspValue) return [];
  const targetApex = (extractApexDomain(targetDomain) || targetDomain).toLowerCase();
  const found = new Set<string>();
  const tokens = cspValue.split(/[\s,;]+/);

  for (const tok of tokens) {
    const clean = tok.trim().replace(/^['"]|['"]$/g, '').toLowerCase();
    if (!clean || clean.startsWith("'") || clean === 'none' || clean === 'self' || clean === 'unsafe-inline' || clean === 'unsafe-eval') {
      continue;
    }
    if (clean === '*' || clean === 'https:' || clean === 'http:' || clean === 'data:' || clean === 'blob:' || clean === 'ws:' || clean === 'wss:') {
      continue;
    }
    let hostCandidate = clean.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
    hostCandidate = hostCandidate.replace(/^\*\./, '');
    if (/^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/.test(hostCandidate)) {
      const apex = extractApexDomain(hostCandidate) || hostCandidate;
      if (apex !== targetApex && hostCandidate !== targetDomain.toLowerCase()) {
        found.add(hostCandidate);
      }
    }
  }

  return Array.from(found).sort();
}

export function extractAnalyticsIdsFromText(text: string): string[] {
  if (!text) return [];
  const sample = text.length > MAX_HTML_RECON_BYTES ? text.slice(0, MAX_HTML_RECON_BYTES) : text;
  const found = new Set<string>();

  const collect = (regex: RegExp, prefix: string, transform?: (m: string) => string) => {
    let count = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(sample)) !== null && count < 40) {
      const val = (transform ? transform(match[1]) : match[1]).trim();
      if (val) {
        found.add(`${prefix}: ${val}`);
        count++;
      }
    }
  };

  // Google Analytics 4 (G-XXXXXXXXXX)
  collect(/\b(G-[A-Z0-9]{8,12})\b/g, 'GA4');
  // Google Universal Analytics (UA-XXXXXX-X)
  collect(/\b(UA-\d{4,12}-\d{1,4})\b/g, 'UA');
  // Google Tag Manager (GTM-XXXXXXX)
  collect(/\b(GTM-[A-Z0-9]{5,10})\b/g, 'GTM');
  // Google Ads Conversion (AW-XXXXXXXXX)
  collect(/\b(AW-\d{7,12})\b/g, 'Google Ads');
  // Google AdSense Publisher ID (ca-pub-XXXXXXXXXXXXXXXX)
  collect(/\b(ca-pub-\d{12,20})\b/gi, 'AdSense', (s) => s.toLowerCase());
  // Meta / Facebook Pixel
  collect(/fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]/gi, 'Meta Pixel');
  collect(/facebook\.com\/tr\?[^"'\s]*id=(\d{10,20})/gi, 'Meta Pixel');
  // Microsoft Clarity
  collect(/clarity\.ms\/tag\/([a-z0-9]{6,16})/gi, 'MS Clarity', (s) => s.toLowerCase());
  collect(/\(\s*window\s*,\s*document\s*,\s*['"]clarity['"][^)]{0,160}['"]([a-z0-9]{6,16})['"]\s*\)/gi, 'MS Clarity', (s) => s.toLowerCase());
  // Hotjar
  collect(/hjid\s*[:=]\s*(\d{5,12})/gi, 'Hotjar');
  // HubSpot Portal ID
  collect(/js\.hs-scripts\.com\/(\d{5,12})\.js/gi, 'HubSpot');
  collect(/js\.hsforms\.net\/forms\/[^"'\s]*portalId[=:](\d{5,12})/gi, 'HubSpot');
  // Cloudflare Web Analytics Beacon
  collect(/static\.cloudflareinsights\.com\/beacon\.min\.js[^"']*token['":\s=]+([0-9a-f]{24,40})/gi, 'Cloudflare Beacon', (s) => s.toLowerCase());
  // TikTok Pixel
  collect(/ttq\.load\(\s*['"]([A-Z0-9]{12,28})['"]/gi, 'TikTok Pixel');
  // LinkedIn Insight Tag
  collect(/_linkedin_partner_id\s*=\s*["'](\d{5,12})["']/gi, 'LinkedIn Insight');
  // Pinterest Tag
  collect(/pintrk\(\s*['"]load['"]\s*,\s*['"](\d{10,20})['"]/gi, 'Pinterest Tag');
  // Intercom App ID
  collect(/widget\.intercom\.io\/widget\/([a-z0-9]{6,14})/gi, 'Intercom', (s) => s.toLowerCase());
  // Sentry DSN
  collect(/https:\/\/[0-9a-f]{16,40}@[a-z0-9.-]+\/(\d{4,12})/gi, 'Sentry Project');
  // PostHog Key
  collect(/posthog\.init\(\s*['"](phc_[A-Za-z0-9_-]{20,60})['"]/g, 'PostHog');
  // Plausible Domain
  collect(/plausible\.io\/js\/script[^"']*[^>]*data-domain=["']([a-z0-9.-]+)["']/gi, 'Plausible', (s) => s.toLowerCase());

  return Array.from(found).sort();
}

function normalizeHttpUrl(rawUrl: string | null | undefined, baseUrl: string): string | null {
  if (!rawUrl) return null;
  const trimmed = rawUrl.trim();
  if (!trimmed || trimmed.startsWith('#') || /^(?:javascript|data|vbscript|mailto|tel):/i.test(trimmed)) {
    return null;
  }
  try {
    const resolved = new URL(trimmed, baseUrl);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
      return null;
    }
    return resolved.toString();
  } catch {
    return null;
  }
}

function decodeHtmlEntitiesMinimal(str: string): string {
  return str
    .replace(/&copy;|&#169;|&#xa9;/gi, '©')
    .replace(/&reg;|&#174;/gi, '®')
    .replace(/&trade;|&#8482;/gi, '™')
    .replace(/&ndash;|&#8211;/gi, '-')
    .replace(/&mdash;|&#8212;/gi, '-')
    .replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

interface ParsedHtmlModel {
  title?: string;
  htmlLang?: string;
  metas: Array<{ name: string; property: string; content: string }>;
  links: Array<{ rel: string; href: string }>;
  scripts: Array<{ src: string; inlineText: string }>;
  images: string[];
  media: string[];
  iframes: string[];
  forms: string[];
  anchors: string[];
  noscripts: string[];
  inlineStyles: string[];
  domSignals: string[];
  footerTexts: string[];
  bodyTailText: string;
}

function parseAttributesFromTag(attrText: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const attrRegex = /([a-zA-Z0-9_:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = attrRegex.exec(attrText)) !== null && count < 40) {
    const key = m[1].toLowerCase();
    const val = m[2] ?? m[3] ?? m[4] ?? '';
    attrs[key] = decodeHtmlEntitiesMinimal(val);
    count++;
  }
  return attrs;
}

/**
 * Pure-browser DOMParser extractor (zero execution) vs deterministic Node tag scanner.
 */
function parseHtmlInert(html: string): ParsedHtmlModel {
  const bounded = html.length > MAX_HTML_RECON_BYTES ? html.slice(0, MAX_HTML_RECON_BYTES) : html;
  const model: ParsedHtmlModel = {
    metas: [],
    links: [],
    scripts: [],
    images: [],
    media: [],
    iframes: [],
    forms: [],
    anchors: [],
    noscripts: [],
    inlineStyles: [],
    domSignals: [],
    footerTexts: [],
    bodyTailText: '',
  };

  if (typeof DOMParser !== 'undefined') {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(bounded, 'text/html');
      model.title = doc.title ? doc.title.trim().slice(0, 300) : undefined;
      model.htmlLang = doc.documentElement?.getAttribute('lang')?.trim() || undefined;

      doc.querySelectorAll('meta').forEach((el) => {
        const name = (el.getAttribute('name') || el.getAttribute('http-equiv') || '').trim().toLowerCase();
        const property = (el.getAttribute('property') || '').trim().toLowerCase();
        const content = (el.getAttribute('content') || '').trim();
        if ((name || property) && content) {
          model.metas.push({ name, property, content: content.slice(0, 500) });
        }
      });

      doc.querySelectorAll('link[href]').forEach((el) => {
        const rel = (el.getAttribute('rel') || '').trim().toLowerCase();
        const href = (el.getAttribute('href') || '').trim();
        if (href) model.links.push({ rel, href });
      });

      doc.querySelectorAll('script').forEach((el) => {
        const src = (el.getAttribute('src') || '').trim();
        const inlineText = !src ? (el.textContent || '').slice(0, 40000) : '';
        model.scripts.push({ src, inlineText });
      });

      doc.querySelectorAll('img[src]').forEach((el) => {
        const src = (el.getAttribute('src') || '').trim();
        if (src) model.images.push(src);
      });

      doc.querySelectorAll('video[src], audio[src], source[src]').forEach((el) => {
        const src = (el.getAttribute('src') || '').trim();
        if (src) model.media.push(src);
      });

      doc.querySelectorAll('iframe[src]').forEach((el) => {
        const src = (el.getAttribute('src') || '').trim();
        if (src) model.iframes.push(src);
      });

      doc.querySelectorAll('form[action]').forEach((el) => {
        const action = (el.getAttribute('action') || '').trim();
        if (action) model.forms.push(action);
      });

      doc.querySelectorAll('a[href]').forEach((el) => {
        const href = (el.getAttribute('href') || '').trim();
        if (href) model.anchors.push(href);
      });

      doc.querySelectorAll('noscript').forEach((el) => {
        const txt = (el.textContent || '').trim().slice(0, 4000);
        if (txt) model.noscripts.push(txt);
      });

      doc.querySelectorAll('style').forEach((el) => {
        const txt = (el.textContent || '').slice(0, 20000);
        if (txt) model.inlineStyles.push(txt);
      });

      // Structural DOM framework & mount detection (inert selectors only)
      if (doc.querySelector('#__next, #__NEXT_DATA__')) model.domSignals.push('Mount: #__next (Next.js)');
      if (doc.querySelector('#__nuxt, #__NUXT_DATA__')) model.domSignals.push('Mount: #__nuxt (Nuxt)');
      if (doc.querySelector('#root, [data-reactroot]')) model.domSignals.push('Mount: React Root');
      if (doc.querySelector('[ng-version]')) model.domSignals.push('Mount: Angular (ng-version)');
      if (doc.querySelector('[data-svelte-h], [class*="svelte-"]')) model.domSignals.push('Mount: Svelte');
      if (doc.querySelector('[data-wf-domain], [data-wf-site]')) model.domSignals.push('DOM: Webflow Site Attrs');
      if (doc.querySelector('[class*="wp-block-"], #wpadminbar')) model.domSignals.push('DOM: WordPress Gutenberg');
      if (doc.querySelector('[id*="shopify-section"]')) model.domSignals.push('DOM: Shopify Sections');

      // Footer & copyright container text extraction (inert DOMParser textContent only)
      doc
        .querySelectorAll('footer, [role="contentinfo"], [id*="footer" i], [class*="footer" i], [id*="copyright" i], [class*="copyright" i]')
        .forEach((el) => {
          if (model.footerTexts.length >= 25) return;
          const txt = (el.textContent || '').replace(/\s+/g, ' ').trim();
          if (txt && txt.length >= 6) {
            model.footerTexts.push(txt.slice(0, 4000));
          }
        });
      model.bodyTailText = (doc.body?.textContent || '').replace(/\s+/g, ' ').trim().slice(-12000);

      return model;
    } catch {
      // Fallback to static tag scanner below if DOMParser throws
    }
  }

  // Deterministic linear-time Node/fallback tag scanner
  const htmlTagMatch = bounded.match(/<html\b([^>]{0,500})>/i);
  if (htmlTagMatch) {
    const htmlAttrs = parseAttributesFromTag(htmlTagMatch[1]);
    if (htmlAttrs.lang) model.htmlLang = htmlAttrs.lang;
    if (htmlAttrs['data-wf-domain'] || htmlAttrs['data-wf-site']) {
      model.domSignals.push('DOM: Webflow Site Attrs');
    }
  }

  const titleMatch = bounded.match(/<title[^>]*>([\s\S]{0,400}?)<\/title>/i);
  if (titleMatch) {
    model.title = decodeHtmlEntitiesMinimal(titleMatch[1]).slice(0, 300);
  }

  const metaRegex = /<meta\b([^>]{1,1000})>/gi;
  let m: RegExpExecArray | null;
  while ((m = metaRegex.exec(bounded)) !== null && model.metas.length < 150) {
    const attrs = parseAttributesFromTag(m[1]);
    const name = (attrs.name || attrs['http-equiv'] || '').toLowerCase();
    const property = (attrs.property || '').toLowerCase();
    const content = attrs.content || '';
    if ((name || property) && content) {
      model.metas.push({ name, property, content: content.slice(0, 500) });
    }
  }

  const linkRegex = /<link\b([^>]{1,1000})>/gi;
  while ((m = linkRegex.exec(bounded)) !== null && model.links.length < 200) {
    const attrs = parseAttributesFromTag(m[1]);
    if (attrs.href) {
      model.links.push({ rel: (attrs.rel || '').toLowerCase(), href: attrs.href });
    }
  }

  const scriptRegex = /<script\b([^>]{0,1000})>([\s\S]{0,60000}?)<\/script>/gi;
  while ((m = scriptRegex.exec(bounded)) !== null && model.scripts.length < 200) {
    const attrs = parseAttributesFromTag(m[1]);
    model.scripts.push({
      src: attrs.src || '',
      inlineText: attrs.src ? '' : m[2].slice(0, 40000),
    });
  }

  const imgRegex = /<img\b([^>]{1,1000})>/gi;
  while ((m = imgRegex.exec(bounded)) !== null && model.images.length < 150) {
    const attrs = parseAttributesFromTag(m[1]);
    if (attrs.src) model.images.push(attrs.src);
  }

  const mediaRegex = /<(?:video|audio|source)\b([^>]{1,1000})>/gi;
  while ((m = mediaRegex.exec(bounded)) !== null && model.media.length < 100) {
    const attrs = parseAttributesFromTag(m[1]);
    if (attrs.src) model.media.push(attrs.src);
  }

  const iframeRegex = /<iframe\b([^>]{1,1000})>/gi;
  while ((m = iframeRegex.exec(bounded)) !== null && model.iframes.length < 50) {
    const attrs = parseAttributesFromTag(m[1]);
    if (attrs.src) model.iframes.push(attrs.src);
  }

  const formRegex = /<form\b([^>]{1,1000})>/gi;
  while ((m = formRegex.exec(bounded)) !== null && model.forms.length < 50) {
    const attrs = parseAttributesFromTag(m[1]);
    if (attrs.action) model.forms.push(attrs.action);
  }

  const aRegex = /<a\b([^>]{1,1000})>/gi;
  while ((m = aRegex.exec(bounded)) !== null && model.anchors.length < 300) {
    const attrs = parseAttributesFromTag(m[1]);
    if (attrs.href) model.anchors.push(attrs.href);
  }

  const noscriptRegex = /<noscript[^>]*>([\s\S]{0,8000}?)<\/noscript>/gi;
  while ((m = noscriptRegex.exec(bounded)) !== null && model.noscripts.length < 30) {
    model.noscripts.push(m[1]);
  }

  const styleRegex = /<style[^>]*>([\s\S]{0,20000}?)<\/style>/gi;
  while ((m = styleRegex.exec(bounded)) !== null && model.inlineStyles.length < 20) {
    model.inlineStyles.push(m[1]);
  }

  if (/id=["']__next["']|id=["']__NEXT_DATA__["']/.test(bounded)) model.domSignals.push('Mount: #__next (Next.js)');
  if (/id=["']__nuxt["']|id=["']__NUXT_DATA__["']/.test(bounded)) model.domSignals.push('Mount: #__nuxt (Nuxt)');
  if (/id=["']root["']|data-reactroot/i.test(bounded)) model.domSignals.push('Mount: React Root');
  if (/\bng-version=/i.test(bounded)) model.domSignals.push('Mount: Angular (ng-version)');
  if (/data-svelte-h|class=["'][^"']*svelte-/i.test(bounded)) model.domSignals.push('Mount: Svelte');
  if (/data-wf-domain|data-wf-site/i.test(bounded)) model.domSignals.push('DOM: Webflow Site Attrs');
  if (/wp-block-|id=["']wpadminbar["']/i.test(bounded)) model.domSignals.push('DOM: WordPress Gutenberg');
  if (/shopify-section/i.test(bounded)) model.domSignals.push('DOM: Shopify Sections');

  // Strip scripts/styles then extract safe plain text from <footer> / copyright blocks (Node fallback)
  const stripHtmlToText = (rawFragment: string): string => {
    const noScriptsOrStyles = rawFragment
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
      .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ');
    return decodeHtmlEntitiesMinimal(noScriptsOrStyles.replace(/<[^>]+>/g, ' '));
  };

  const footerRegex = /<footer\b[^>]*>([\s\S]{0,60000}?)<\/footer>/gi;
  while ((m = footerRegex.exec(bounded)) !== null && model.footerTexts.length < 15) {
    const txt = stripHtmlToText(m[1]);
    if (txt && txt.length >= 6) model.footerTexts.push(txt.slice(0, 4000));
  }

  const copyrightContainerRegex =
    /<(?:div|section|p|span|small)\b[^>]*(?:contentinfo|footer|copyright)[^>]*>([\s\S]{0,8000}?)<\/(?:div|section|p|span|small)>/gi;
  while ((m = copyrightContainerRegex.exec(bounded)) !== null && model.footerTexts.length < 25) {
    const txt = stripHtmlToText(m[1]);
    if (txt && txt.length >= 6) model.footerTexts.push(txt.slice(0, 4000));
  }

  const rawTail = stripHtmlToText(bounded.slice(-40000));
  model.bodyTailText = (bounded.length > 40000 ? rawTail.replace(/^\S*\s+/, '') : rawTail).slice(-12000);

  return model;
}

function cleanCopyrightEntity(rawNotice: string): string {
  let entity = rawNotice
    .replace(/copyright/gi, ' ')
    .replace(/\(c\)|©/gi, ' ')
    .replace(/\ball\s+rights\s+reserved\b.*$/i, ' ')
    .replace(/\b(?:privacy\s+policy|terms\s+(?:of\s+(?:use|service)|&\s*conditions)|cookie\s+policy|sitemap|powered\s+by)\b.*$/i, ' ')
    .replace(/\b(?:19|20)\d{2}(?:\s*[-–—,/]\s*(?:(?:19|20)\d{2}|present))?/gi, ' ')
    .replace(/^[\s.,:;\-–—|/()]+/, '')
    .replace(/[\s,:;\-–—|/()]+$/, '')
    .replace(/^by\s+/i, '')
    .replace(/\s+/g, ' ')
    .trim();

  // Strip trailing period unless it belongs to a corporate abbreviation (e.g. Inc., Ltd., Corp., Co.)
  if (entity.endsWith('.') && !/\b(?:inc|ltd|corp|co|jr|sr)\.?$/i.test(entity)) {
    entity = entity.slice(0, -1).trim();
  }

  // Require at least 2 alphabetic characters and reject generic noise
  if (!/[a-zA-Z]{2,}/.test(entity)) return '';
  if (/^(?:reserved|rights|all|website|home|inc|llc|ltd|corp|present)$/i.test(entity)) return '';
  return entity;
}

function extractFooterCopyrights(
  footerTexts: string[],
  bodyTailText: string
): { footerCopyrights: string[]; copyrightEntities: string[] } {
  const noticesSet = new Set<string>();
  const entityMap = new Map<string, string>();

  const cleanNotice = (raw: string): string => {
    let s = decodeHtmlEntitiesMinimal(raw)
      .replace(/\s*(?:All\s+rights\s+reserved|Privacy\s+Policy|Terms\s+of\s+(?:Use|Service)|Terms\s*&\s*Conditions|Cookie\s+Policy|Powered\s+by)\b.*$/i, '')
      .replace(/[\s|•·\-–—:/]+$/, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (s.endsWith('.') && !/\b(?:inc|ltd|corp|co|jr|sr)\.?$/i.test(s)) {
      s = s.slice(0, -1).trim();
    }
    if (s.length > 130) s = s.slice(0, 127).trim() + '...';
    return s;
  };

  const scanChunks = (chunks: string[]) => {
    for (const chunk of chunks) {
      if (!chunk) continue;
      // Split on visual separators so side-by-side nav links don't bleed into the notice
      const segments = chunk.split(/[|\n\r•·]+/);
      for (const seg of segments) {
        const trimmed = seg.trim();
        if (!trimmed || trimmed.length < 6) continue;

        let matchedP1OnSegment = false;
        // Pattern 1: Symbol/Copyright first (e.g. "© 2026 GitHub, Inc.", "©1998–2026 by individual mozilla.org contributors")
        const p1 =
          /(?:©|Copyright(?:\s*(?:©|\(c\)))?|\(c\))\s*(?:(?:19|20)\d{2}(?:\s*[-–—,/]\s*(?:(?:19|20)\d{2}|present))?)?\s*(.{2,120}?)(?=\.\s+(?:All\b|Content\b|Privacy\b|Terms\b|Portions\b|Unless\b|[A-Z©])|[;\n\r|•·]|$)/gi;
        let match: RegExpExecArray | null;
        while ((match = p1.exec(trimmed)) !== null && noticesSet.size < 12) {
          const notice = cleanNotice(match[0]);
          if (notice.length < 6 || !/[a-zA-Z]{2,}/.test(notice)) continue;
          const entity = cleanCopyrightEntity(notice);
          if (!entity) continue;
          matchedP1OnSegment = true;
          noticesSet.add(notice);
          const normKey = entity.toLowerCase();
          if (!entityMap.has(normKey)) {
            entityMap.set(normKey, entity);
          }
        }

        // Pattern 2: Entity first, then © / Copyright + Year (only when symbol isn't already followed by entity on this segment)
        if (!matchedP1OnSegment) {
          const p2 =
            /(?:^|[.;:!?]\s+)([A-Z][A-Za-z0-9\s,&.'-]{1,50}?)\s*(?:©|Copyright(?:\s*(?:©|\(c\)))?|\(c\))\s*(?:19|20)\d{2}(?:\s*[-–—]\s*(?:(?:19|20)\d{2}|present))?(?=$|[.\s,;|])/g;
          while ((match = p2.exec(trimmed)) !== null && noticesSet.size < 12) {
            const notice = cleanNotice(match[1] + ' ' + match[0].slice(match[0].indexOf(match[1]) + match[1].length).trim());
            if (notice.length < 6 || !/[a-zA-Z]{2,}/.test(notice)) continue;
            const entity = cleanCopyrightEntity(match[1]);
            if (!entity) continue;
            noticesSet.add(notice);
            const normKey = entity.toLowerCase();
            if (!entityMap.has(normKey)) {
              entityMap.set(normKey, entity);
            }
          }
        }
      }
    }
  };

  if (footerTexts.length > 0) {
    scanChunks(footerTexts);
  }
  // Fallback to page tail only if explicit footer containers yielded nothing
  if (noticesSet.size === 0 && bodyTailText) {
    scanChunks([bodyTailText]);
  }

  return {
    footerCopyrights: Array.from(noticesSet).sort(),
    copyrightEntities: Array.from(entityMap.values()).sort(),
  };
}

function fingerprintTechnologies(params: {
  headers: Record<string, string>;
  generator?: string;
  scriptUrls: string[];
  stylesheetUrls: string[];
  domSignals: string[];
  htmlSample: string;
}): string[] {
  const techs = new Set<string>();
  const h = params.headers;
  const server = (h['server'] || '').toLowerCase();
  const poweredBy = (h['x-powered-by'] || '').toLowerCase();
  const gen = (params.generator || h['x-generator'] || '').toLowerCase();
  const assets = [...params.scriptUrls, ...params.stylesheetUrls].join(' ').toLowerCase();
  const htmlLower = params.htmlSample.slice(0, 120000).toLowerCase();

  // Edge / CDN / Hosting
  if (h['cf-ray'] || server.includes('cloudflare')) techs.add('Cloudflare CDN/WAF');
  if (h['x-vercel-id'] || server.includes('vercel')) techs.add('Vercel Edge');
  if (h['x-github-request-id'] || server.includes('github.com')) techs.add('GitHub Pages');
  if (h['x-amz-cf-id'] || server.includes('cloudfront')) techs.add('AWS CloudFront');
  if (h['x-served-by']?.toLowerCase().includes('cache-') || server.includes('fastly')) techs.add('Fastly CDN');
  if (server.includes('nginx')) techs.add('Nginx');
  if (server.includes('apache')) techs.add('Apache HTTP');
  if (server.includes('openresty')) techs.add('OpenResty');
  if (server.includes('envoy')) techs.add('Envoy Proxy');
  if (server.includes('gws') || server.includes('esf') || server.includes('sffe')) techs.add('Google Front End (GFE)');
  if (h['x-shopify-stage'] || assets.includes('cdn.shopify.com')) techs.add('Shopify');
  if (h['x-wix-request-id'] || assets.includes('static.wixstatic.com')) techs.add('Wix');

  // Server Runtime
  if (poweredBy.includes('express')) techs.add('Express.js');
  if (poweredBy.includes('next.js') || gen.includes('next.js') || assets.includes('/_next/') || params.domSignals.some((d) => d.includes('Next.js'))) {
    techs.add('Next.js');
  }
  if (poweredBy.includes('php') || gen.includes('php')) techs.add('PHP');
  if (poweredBy.includes('asp.net')) techs.add('ASP.NET');

  // CMS & Static Site Builders
  if (gen.includes('wordpress') || assets.includes('/wp-content/') || assets.includes('/wp-includes/')) techs.add('WordPress');
  if (gen.includes('drupal') || h['x-drupal-cache'] || assets.includes('/sites/default/files')) techs.add('Drupal');
  if (gen.includes('ghost') || htmlLower.includes('ghost-url')) techs.add('Ghost CMS');
  if (gen.includes('jekyll') || htmlLower.includes('jekyll v')) techs.add('Jekyll');
  if (gen.includes('hugo')) techs.add('Hugo');
  if (gen.includes('astro')) techs.add('Astro');
  if (gen.includes('webflow') || params.domSignals.some((d) => d.includes('Webflow'))) techs.add('Webflow');
  if (gen.includes('squarespace') || assets.includes('squarespace.com')) techs.add('Squarespace');

  // Frontend Frameworks & Libraries
  if (params.domSignals.some((d) => d.includes('Nuxt')) || assets.includes('/_nuxt/')) techs.add('Nuxt / Vue');
  if (params.domSignals.some((d) => d.includes('React'))) techs.add('React');
  if (params.domSignals.some((d) => d.includes('Angular'))) techs.add('Angular');
  if (params.domSignals.some((d) => d.includes('Svelte'))) techs.add('Svelte');
  if (assets.includes('jquery') || assets.includes('/jquery-')) techs.add('jQuery');
  if (assets.includes('bootstrap')) techs.add('Bootstrap');
  if (htmlLower.includes('tailwindcss') || assets.includes('tailwind')) techs.add('Tailwind CSS');
  if (assets.includes('recaptcha') || assets.includes('google.com/recaptcha')) techs.add('Google reCAPTCHA');
  if (assets.includes('challenges.cloudflare.com/turnstile')) techs.add('Cloudflare Turnstile');
  if (assets.includes('js.stripe.com')) techs.add('Stripe Checkout');

  return Array.from(techs).sort();
}

export function analyzeHtmlRecon(
  htmlText: string,
  baseUrl: string,
  sanitizedHeaders: Record<string, string>,
  targetDomain: string
): StaticHtmlReconResult {
  const model = parseHtmlInert(htmlText);
  const targetApex = (extractApexDomain(targetDomain) || targetDomain).toLowerCase();

  let htmlDescription: string | undefined;
  let htmlGenerator: string | undefined;
  let htmlAuthor: string | undefined;
  let htmlRobots: string | undefined;
  let openGraphSiteName: string | undefined;
  let twitterSite: string | undefined;
  const htmlVerificationTokens: VerificationTokenItem[] = [];

  for (const meta of model.metas) {
    const key = meta.name || meta.property;
    if (!key || !meta.content) continue;
    if (key === 'description' && !htmlDescription) htmlDescription = meta.content;
    else if (key === 'generator' && !htmlGenerator) htmlGenerator = meta.content;
    else if (key === 'author' && !htmlAuthor) htmlAuthor = meta.content;
    else if (key === 'robots' && !htmlRobots) htmlRobots = meta.content;
    else if (key === 'og:site_name' && !openGraphSiteName) openGraphSiteName = meta.content;
    else if (key === 'twitter:site' && !twitterSite) twitterSite = meta.content;
    else if (key === 'google-site-verification') {
      htmlVerificationTokens.push({ provider: 'Google Site Verification (Meta)', token: meta.content, raw: meta.content });
    } else if (key === 'msvalidate.01') {
      htmlVerificationTokens.push({ provider: 'Bing / Microsoft Webmaster (Meta)', token: meta.content, raw: meta.content });
    } else if (key === 'facebook-domain-verification') {
      htmlVerificationTokens.push({ provider: 'Meta Domain Verification (Meta)', token: meta.content, raw: meta.content });
    } else if (key === 'yandex-verification') {
      htmlVerificationTokens.push({ provider: 'Yandex Webmaster (Meta)', token: meta.content, raw: meta.content });
    } else if (key === 'p:domain_verify') {
      htmlVerificationTokens.push({ provider: 'Pinterest Verification (Meta)', token: meta.content, raw: meta.content });
    } else if (key === 'apple-itunes-app') {
      htmlVerificationTokens.push({ provider: 'Apple App SmartBanner (Meta)', token: meta.content, raw: meta.content });
    }
  }

  let canonicalUrl: string | undefined;
  const stylesheetSet = new Set<string>();
  const iconSet = new Set<string>();
  const preconnectHosts = new Set<string>();

  for (const link of model.links) {
    const url = normalizeHttpUrl(link.href, baseUrl);
    if (!url) continue;
    if (link.rel.includes('canonical') && !canonicalUrl) {
      canonicalUrl = url;
    } else if (link.rel.includes('stylesheet')) {
      stylesheetSet.add(url);
    } else if (link.rel.includes('icon') || link.rel === 'manifest') {
      iconSet.add(url);
    } else if (link.rel.includes('preconnect') || link.rel.includes('dns-prefetch')) {
      try {
        preconnectHosts.add(new URL(url).hostname.toLowerCase());
      } catch {}
    }
  }

  const scriptSet = new Set<string>();
  const inlineScriptParts: string[] = [];
  for (const s of model.scripts) {
    const resolved = normalizeHttpUrl(s.src, baseUrl);
    if (resolved) scriptSet.add(resolved);
    if (s.inlineText) inlineScriptParts.push(s.inlineText);
  }

  const mediaSet = new Set<string>();
  for (const raw of [...model.images, ...model.media]) {
    const resolved = normalizeHttpUrl(raw, baseUrl);
    if (resolved) mediaSet.add(resolved);
  }

  const cssUrlSet = new Set<string>();
  for (const css of model.inlineStyles) {
    const cssUrlRegex = /url\(\s*['"]?([^'"()\s]+)['"]?\s*\)/gi;
    let m: RegExpExecArray | null;
    while ((m = cssUrlRegex.exec(css)) !== null && cssUrlSet.size < 40) {
      const resolved = normalizeHttpUrl(m[1], baseUrl);
      if (resolved) cssUrlSet.add(resolved);
    }
  }

  const iframeHostSet = new Set<string>();
  for (const raw of model.iframes) {
    const resolved = normalizeHttpUrl(raw, baseUrl);
    if (!resolved) continue;
    try {
      iframeHostSet.add(new URL(resolved).hostname.toLowerCase());
    } catch {}
  }

  const formHostSet = new Set<string>();
  for (const raw of model.forms) {
    const resolved = normalizeHttpUrl(raw, baseUrl);
    if (!resolved) continue;
    try {
      formHostSet.add(new URL(resolved).hostname.toLowerCase());
    } catch {}
  }

  const scriptUrls = Array.from(scriptSet).sort();
  const stylesheetUrls = Array.from(stylesheetSet).sort();
  const iconUrls = Array.from(iconSet).sort();
  const mediaUrls = Array.from(mediaSet).sort();
  const iframeHosts = Array.from(iframeHostSet).sort();
  const formActionHosts = Array.from(formHostSet).sort();

  const cspExternalDomains = extractCspExternalDomains(
    sanitizedHeaders['content-security-policy'],
    targetDomain
  );

  // Aggregate external domains from all discovered resource/link/CSP/form/iframe origins
  const externalDomainSet = new Set<string>(cspExternalDomains);
  const candidateUrls: string[] = [
    ...scriptUrls,
    ...stylesheetUrls,
    ...iconUrls,
    ...mediaUrls,
    ...Array.from(cssUrlSet),
  ];

  for (const raw of [...model.anchors, ...model.iframes, ...model.forms]) {
    const resolved = normalizeHttpUrl(raw, baseUrl);
    if (resolved) candidateUrls.push(resolved);
  }

  for (const host of preconnectHosts) {
    const apex = extractApexDomain(host) || host;
    if (apex !== targetApex && host !== targetDomain.toLowerCase()) {
      externalDomainSet.add(host);
    }
  }

  for (const u of candidateUrls) {
    try {
      const h = new URL(u).hostname.toLowerCase();
      const apex = extractApexDomain(h) || h;
      if (h && apex !== targetApex && h !== targetDomain.toLowerCase()) {
        externalDomainSet.add(h);
      }
    } catch {}
  }

  // Extract Analytics IDs from bounded raw HTML, script src URLs, <noscript>, and inline script text (never executed)
  const analyticsCorpus = [
    htmlText.slice(0, MAX_HTML_RECON_BYTES),
    scriptUrls.join('\n'),
    model.noscripts.join('\n'),
    inlineScriptParts.join('\n'),
  ].join('\n');
  const analyticsIds = extractAnalyticsIdsFromText(analyticsCorpus);

  const technologies = fingerprintTechnologies({
    headers: sanitizedHeaders,
    generator: htmlGenerator,
    scriptUrls,
    stylesheetUrls,
    domSignals: model.domSignals,
    htmlSample: htmlText,
  });

  const domMarkers = Array.from(
    new Set([
      ...model.domSignals,
      ...(model.htmlLang ? [`HTML Lang: ${model.htmlLang}`] : []),
      ...iframeHosts.map((h) => `Iframe Origin: ${h}`),
      ...formActionHosts.map((h) => `Form Action: ${h}`),
    ])
  ).sort();

  const domStats = `Forms: ${model.forms.length} | Iframes: ${model.iframes.length} | Scripts: ${scriptUrls.length} | Stylesheets: ${stylesheetUrls.length} | Media/Icons: ${mediaUrls.length + iconUrls.length}`;

  const resourceSummary: string[] = [
    ...iconUrls.slice(0, 10).map((u) => `Icon/Manifest: ${u}`),
    ...stylesheetUrls.slice(0, 15).map((u) => `Stylesheet: ${u}`),
    ...mediaUrls.slice(0, 10).map((u) => `Media/Image: ${u}`),
  ].sort();

  const httpHeaderSummary = Object.keys(sanitizedHeaders)
    .sort()
    .map((k) => {
      const val = sanitizedHeaders[k];
      return `${k}: ${val.length > 420 ? `${val.slice(0, 417)}...` : val}`;
    });

  const { footerCopyrights, copyrightEntities } = extractFooterCopyrights(
    model.footerTexts,
    model.bodyTailText
  );

  return {
    httpHeaderSummary,
    cspExternalDomains,
    htmlTitle: model.title,
    htmlDescription,
    htmlGenerator,
    htmlAuthor,
    htmlRobots,
    canonicalUrl,
    openGraphSiteName,
    twitterSite,
    htmlVerificationTokens,
    domMarkers,
    domStats,
    scriptUrls,
    resourceSummary,
    analyticsIds,
    footerCopyrights,
    copyrightEntities,
    technologies,
    externalDomains: Array.from(externalDomainSet).sort(),
  };
}

/**
 * Reads a fetch Response body strictly as bounded UTF-8 text without buffering unbounded payloads.
 */
export async function readBoundedResponseText(res: Response, maxBytes: number): Promise<string> {
  if (!res.body || typeof res.body.getReader !== 'function') {
    const text = await res.text();
    return text.length > maxBytes ? text.slice(0, maxBytes) : text;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: false });
  const chunks: string[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;

      const remaining = maxBytes - totalBytes;
      if (remaining <= 0) break;

      if (value.byteLength <= remaining) {
        chunks.push(decoder.decode(value, { stream: true }));
        totalBytes += value.byteLength;
      } else {
        chunks.push(decoder.decode(value.subarray(0, remaining), { stream: false }));
        totalBytes += remaining;
        break;
      }
    }
    const tail = decoder.decode();
    if (tail) chunks.push(tail);
  } finally {
    try {
      await reader.cancel();
    } catch {}
  }

  return chunks.join('');
}

/**
 * Selects up to `maxCount` same-apex / first-party script URLs for passive UTF-8 text scanning
 * (never executed). Skips obvious third-party analytics CDNs whose IDs are already in the URL.
 */
export function selectFirstPartyScriptsForInspection(
  scriptUrls: string[],
  targetDomain: string,
  maxCount = 3
): string[] {
  const targetApex = (extractApexDomain(targetDomain) || targetDomain).toLowerCase();
  const candidates: string[] = [];

  for (const rawUrl of scriptUrls) {
    if (candidates.length >= maxCount) break;
    try {
      const u = new URL(rawUrl);
      const host = u.hostname.toLowerCase();
      const apex = (extractApexDomain(host) || host).toLowerCase();
      if (apex !== targetApex && host !== targetDomain.toLowerCase()) continue;
      // Prioritize inline/app/main/chunk JS files
      candidates.push(rawUrl);
    } catch {}
  }

  return candidates;
}

export interface SubdomainWebProbeEntry {
  host: string;
  httpWebServer?: string;
  httpStatusCode?: number;
  webFinalUrl?: string;
  inspectedScriptsCount?: number;
  recon?: StaticHtmlReconResult;
  fallbackHeaders?: string[];
}

export interface AggregatedWebReconResult {
  httpWebServer?: string;
  httpStatusCode?: number;
  httpHeaderSummary?: string[];
  cspExternalDomains?: string[];
  webReconMode: 'server-direct' | 'browser-cors' | 'cors-blocked' | 'unreachable';
  webFinalUrl?: string;
  inspectedScriptsCount?: number;
  webReconProbedHostsCount: number;
  webReconReachableHosts: string[];
  htmlTitle?: string;
  htmlDescription?: string;
  htmlGenerator?: string;
  htmlAuthor?: string;
  htmlRobots?: string;
  canonicalUrl?: string;
  openGraphSiteName?: string;
  twitterSite?: string;
  htmlVerificationTokens?: VerificationTokenItem[];
  domMarkers?: string[];
  domStats?: string;
  scriptUrls?: string[];
  resourceSummary?: string[];
  analyticsIds?: string[];
  footerCopyrights?: string[];
  copyrightEntities?: string[];
  technologies?: string[];
  externalDomains?: string[];
}

export function mergeSubdomainWebRecon(
  apexDomain: string,
  entries: SubdomainWebProbeEntry[],
  totalProbedCount: number,
  successMode: 'server-direct' | 'browser-cors'
): AggregatedWebReconResult {
  if (!entries || entries.length === 0) {
    return {
      webReconMode: successMode === 'server-direct' ? 'unreachable' : 'cors-blocked',
      webReconProbedHostsCount: totalProbedCount,
      webReconReachableHosts: [],
    };
  }

  const apex = (extractApexDomain(apexDomain) || apexDomain).toLowerCase();
  const wwwHost = `www.${apex}`;

  const rankEntry = (e: SubdomainWebProbeEntry): number => {
    const isOk = typeof e.httpStatusCode === 'number' && e.httpStatusCode >= 200 && e.httpStatusCode < 400;
    const hasHtml = Boolean(e.recon);
    const hostScore = e.host === apex ? 0 : e.host === wwwHost ? 1 : 2;
    return (hasHtml ? 0 : 10) + (isOk ? 0 : 5) + hostScore;
  };

  const ordered = [...entries].sort((a, b) => rankEntry(a) - rankEntry(b));
  const primary = ordered[0];

  const headerSet = new Set<string>();
  const cspSet = new Set<string>();
  const tokenMap = new Map<string, VerificationTokenItem>();
  const domMarkerSet = new Set<string>();
  const scriptSet = new Set<string>();
  const resourceSet = new Set<string>();
  const analyticsSet = new Set<string>();
  const copyrightSet = new Set<string>();
  const entitySet = new Set<string>();
  const techSet = new Set<string>();
  const extDomainSet = new Set<string>();
  const reachableHosts = new Set<string>();
  const serverSet = new Set<string>();

  let totalScriptsInspected = 0;

  for (const entry of ordered) {
    reachableHosts.add(entry.host);
    totalScriptsInspected += entry.inspectedScriptsCount || 0;
    if (entry.httpWebServer) serverSet.add(entry.httpWebServer);

    if (entry.fallbackHeaders) {
      entry.fallbackHeaders.forEach((h) => headerSet.add(h));
    }

    const r = entry.recon;
    if (!r) continue;

    r.httpHeaderSummary.forEach((h) => headerSet.add(h));
    r.cspExternalDomains.forEach((d) => cspSet.add(d));
    r.htmlVerificationTokens.forEach((tok) => {
      const key = `${tok.provider.toLowerCase()}::${tok.token}`;
      if (!tokenMap.has(key)) tokenMap.set(key, tok);
    });
    r.domMarkers.forEach((m) => domMarkerSet.add(m));
    r.scriptUrls.forEach((u) => scriptSet.add(u));
    r.resourceSummary.forEach((resItem) => resourceSet.add(resItem));
    r.analyticsIds.forEach((id) => analyticsSet.add(id));
    r.footerCopyrights.forEach((c) => copyrightSet.add(c));
    r.copyrightEntities.forEach((e) => entitySet.add(e));
    r.technologies.forEach((t) => techSet.add(t));
    r.externalDomains.forEach((d) => extDomainSet.add(d));
  }

  const pickFirst = (getter: (r: StaticHtmlReconResult) => string | undefined): string | undefined => {
    for (const entry of ordered) {
      if (!entry.recon) continue;
      const val = getter(entry.recon);
      if (val) return val;
    }
    return undefined;
  };

  return {
    httpWebServer: primary.httpWebServer || Array.from(serverSet)[0],
    httpStatusCode: primary.httpStatusCode,
    httpHeaderSummary: Array.from(headerSet).sort().slice(0, 120),
    cspExternalDomains: Array.from(cspSet).sort(),
    webReconMode: successMode,
    webFinalUrl: primary.webFinalUrl,
    inspectedScriptsCount: totalScriptsInspected,
    webReconProbedHostsCount: totalProbedCount,
    webReconReachableHosts: Array.from(reachableHosts).sort(),
    htmlTitle: pickFirst((r) => r.htmlTitle),
    htmlDescription: pickFirst((r) => r.htmlDescription),
    htmlGenerator: pickFirst((r) => r.htmlGenerator),
    htmlAuthor: pickFirst((r) => r.htmlAuthor),
    htmlRobots: pickFirst((r) => r.htmlRobots),
    canonicalUrl: pickFirst((r) => r.canonicalUrl),
    openGraphSiteName: pickFirst((r) => r.openGraphSiteName),
    twitterSite: pickFirst((r) => r.twitterSite),
    htmlVerificationTokens: Array.from(tokenMap.values()),
    domMarkers: Array.from(domMarkerSet).sort().slice(0, 100),
    domStats: pickFirst((r) => r.domStats),
    scriptUrls: Array.from(scriptSet).sort().slice(0, 120),
    resourceSummary: Array.from(resourceSet).sort().slice(0, 120),
    analyticsIds: Array.from(analyticsSet).sort(),
    footerCopyrights: Array.from(copyrightSet).sort(),
    copyrightEntities: Array.from(entitySet).sort(),
    technologies: Array.from(techSet).sort(),
    externalDomains: Array.from(extDomainSet).sort().slice(0, 150),
  };
}

