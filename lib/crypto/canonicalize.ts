/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Two semantically-equal JSON documents canonicalize to byte-identical strings,
 * which is what lets us hash and sign JSON reliably. Rules (RFC 8785 §3):
 *   - no whitespace
 *   - object members sorted by property name, compared as UTF-16 code units
 *   - numbers serialized with the ECMAScript Number::toString algorithm
 *   - strings escaped exactly as ECMAScript JSON.stringify does
 * JSON.stringify already implements the number and string rules, so JCS in
 * JavaScript is: recursive key sorting + JSON.stringify for scalars.
 * This is serialization, not cryptography.
 */
export function jcs(value: unknown): string {
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') {
    throw new Error('JCS: value cannot be serialized (undefined / function / symbol)');
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('JCS: non-finite numbers are not valid JSON');
  }
  if (typeof value === 'bigint') throw new Error('JCS: bigint is not valid JSON');
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  const withToJson = value as { toJSON?: (key?: string) => unknown };
  if (typeof withToJson.toJSON === 'function') return jcs(withToJson.toJSON());
  if (Array.isArray(value)) {
    return '[' + value.map((v) => (v === undefined || typeof v === 'function' || typeof v === 'symbol' ? 'null' : jcs(v))).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined && typeof obj[k] !== 'function' && typeof obj[k] !== 'symbol')
    .sort(); // default sort compares UTF-16 code units, as RFC 8785 requires
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(obj[k])).join(',') + '}';
}
