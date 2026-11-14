// SPDX-License-Identifier: AGPL-3.0-or-later

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function getArrayElementSortKey(item: unknown): string {
  if (item === null || item === undefined) return '';
  if (typeof item !== 'object') return String(item);
  if (Array.isArray(item)) return JSON.stringify(item);

  const obj = item as Record<string, unknown>;
  const semanticParts: string[] = [];

  if (typeof obj.eventAction === 'string') semanticParts.push(`event:${obj.eventAction}`);
  if (typeof obj.ldhName === 'string') semanticParts.push(`ldh:${obj.ldhName.toLowerCase()}`);
  if (typeof obj.unicodeName === 'string') semanticParts.push(`uni:${obj.unicodeName.toLowerCase()}`);
  if (typeof obj.rel === 'string') semanticParts.push(`rel:${obj.rel}`);
  if (typeof obj.title === 'string') semanticParts.push(`title:${obj.title}`);
  if (typeof obj.type === 'string') semanticParts.push(`type:${obj.type}`);
  if (Array.isArray(obj.roles)) semanticParts.push(`roles:${obj.roles.join(',')}`);
  if (typeof obj.handle === 'string') semanticParts.push(`handle:${obj.handle}`);
  if (obj.keyTag !== undefined) semanticParts.push(`keyTag:${String(obj.keyTag).padStart(6, '0')}`);
  if (typeof obj.prePath === 'string') semanticParts.push(`prePath:${obj.prePath}`);

  semanticParts.push(JSON.stringify(obj));
  return semanticParts.join('|');
}

export function canonicalizeJson(value: unknown, parentKey?: string): unknown {
  if (value === null || value === undefined || typeof value !== 'object') {
    return value;
  }

  if (Array.isArray(value)) {
    // Preserve jCard vcardArray structural tuple: ["vcard", [[propName, params, type, val], ...]]
    if (
      parentKey === 'vcardArray' &&
      value.length === 2 &&
      value[0] === 'vcard' &&
      Array.isArray(value[1])
    ) {
      const normalizedProps = value[1].map((prop) => {
        if (!Array.isArray(prop)) return canonicalizeJson(prop);
        return prop.map((cell) =>
          cell && typeof cell === 'object' && !Array.isArray(cell)
            ? canonicalizeJson(cell)
            : cell
        );
      });
      normalizedProps.sort((a, b) => {
        const nameA = Array.isArray(a) ? String(a[0] ?? '') : '';
        const nameB = Array.isArray(b) ? String(b[0] ?? '') : '';
        const cmp = compareStrings(nameA, nameB);
        if (cmp !== 0) return cmp;
        return compareStrings(JSON.stringify(a), JSON.stringify(b));
      });
      return ['vcard', normalizedProps];
    }

    const mapped = value.map((item) => canonicalizeJson(item));

    // Preserve natural reading order for prose notice descriptions
    if (parentKey === 'description') {
      return mapped;
    }

    const allPrimitives = mapped.every(
      (item) => item === null || (typeof item !== 'object' && typeof item !== 'function')
    );
    if (allPrimitives) {
      return [...mapped].sort((a, b) => compareStrings(String(a), String(b)));
    }

    const allPlainObjects = mapped.every(
      (item) => item !== null && typeof item === 'object' && !Array.isArray(item)
    );
    if (allPlainObjects) {
      return [...mapped].sort((a, b) =>
        compareStrings(getArrayElementSortKey(a), getArrayElementSortKey(b))
      );
    }

    return mapped;
  }

  const record = value as Record<string, unknown>;
  const sortedKeys = Object.keys(record).sort(compareStrings);
  const result: Record<string, unknown> = {};

  for (const key of sortedKeys) {
    result[key] = canonicalizeJson(record[key], key);
  }

  return result;
}

export function canonicalizeJsonStringify(value: unknown, space = 2): string {
  return JSON.stringify(canonicalizeJson(value), null, space);
}

export function formatCanonicalJsonText(rawText: string): string {
  const trimmed = rawText.trim();
  if (!trimmed) return rawText;
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      return canonicalizeJsonStringify(parsed, 2);
    } catch {
      return rawText;
    }
  }
  return rawText;
}
