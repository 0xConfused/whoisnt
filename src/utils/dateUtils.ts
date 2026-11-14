// SPDX-License-Identifier: AGPL-3.0-or-later

const TZ_OFFSETS: Record<string, string> = {
  UTC: 'Z',
  GMT: 'Z',
  Z: 'Z',
  JST: '+09:00',
  CET: '+01:00',
  CEST: '+02:00',
  EST: '-05:00',
  EDT: '-04:00',
  CST: '-06:00',
  CDT: '-05:00',
  PST: '-08:00',
  PDT: '-07:00',
  BST: '+01:00',
};

export function parseFlexibleDateMs(dateStr?: string): number | null {
  if (!dateStr || typeof dateStr !== 'string') return null;

  let s = dateStr.trim();
  if (!s) return null;

  // Nominet .uk style: "before Aug-1996" or "after Jan-2000"
  const beforeMatch = s.match(/^(?:before|after|circa)\s+([A-Za-z]{3,9})[- ](\d{4})$/i);
  if (beforeMatch) {
    const ts = Date.parse(`01 ${beforeMatch[1]} ${beforeMatch[2]} UTC`);
    return isNaN(ts) ? null : ts;
  }

  // JPRS / slash dates: "1986/08/05" or "2026/04/01 01:03:06 (JST)"
  const slashDateTime = s.match(
    /^(\d{4})[/.](\d{1,2})[/.](\d{1,2})(?:[T\s]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*\(([A-Za-z]+)\))?)?$/
  );
  if (slashDateTime) {
    const [, y, m, d, hh = '00', mm = '00', ss = '00', tz] = slashDateTime;
    const offset = tz ? TZ_OFFSETS[tz.toUpperCase()] ?? 'Z' : 'Z';
    const iso = `${y}-${m.padStart(2, '0')}-${d.padStart(2, '0')}T${hh.padStart(2, '0')}:${mm}:${ss}${offset}`;
    const ts = Date.parse(iso);
    if (!isNaN(ts)) return ts;
  }

  // "YYYY-MM-DD HH:MM:SS (TZ)" or "YYYY-MM-DD HH:MM:SS UTC"
  const spaceIsoTz = s.match(
    /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})(?:\s*\(?([A-Za-z]+)\)?)?$/
  );
  if (spaceIsoTz) {
    const [, datePart, timePart, tz] = spaceIsoTz;
    const offset = tz ? TZ_OFFSETS[tz.toUpperCase()] ?? 'Z' : 'Z';
    const ts = Date.parse(`${datePart}T${timePart}${offset}`);
    if (!isNaN(ts)) return ts;
  }

  // DD-MMM-YYYY (e.g. "23-May-1985", "13-Dec-2034")
  const ddMmmYyyy = s.match(/^(\d{1,2})-([A-Za-z]{3,9})-(\d{4})$/);
  if (ddMmmYyyy) {
    const ts = Date.parse(`${ddMmmYyyy[1]} ${ddMmmYyyy[2]} ${ddMmmYyyy[3]} UTC`);
    if (!isNaN(ts)) return ts;
  }

  // Fallback native Date.parse
  const nativeTs = Date.parse(s);
  return isNaN(nativeTs) ? null : nativeTs;
}
