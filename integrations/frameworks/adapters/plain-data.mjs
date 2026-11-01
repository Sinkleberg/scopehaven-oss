// Plain data only: what an object-path snapshot may carry, checked inside the
// adapter before the values are sent. A JSON round trip turns a Map, a Set or a
// class instance into {} and drops undefined, which a reader would take for
// "nothing there" (an honest-failure reply would then read as agreeing). Such a
// value is refused instead, so the snapshot fails and the run is inconclusive.
// Accepted: null, strings, booleans, finite numbers, arrays and objects whose
// prototype is Object.prototype or null, to a depth of 32.
export class PlainDataError extends Error { constructor(code) { super(`Object-path state: ${code}.`); this.name = 'PlainDataError'; this.code = code; } }

export function plainData(value, depth = 0) {
  if (depth > 32) throw new PlainDataError('depth');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') { if (!Number.isFinite(value)) throw new PlainDataError('number'); return value; }
  if (Array.isArray(value)) return Array.from(value, v => plainData(v, depth + 1));
  if (typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    // A null-prototype copy: a key such as "__proto__" stays an ordinary key.
    const out = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') throw new PlainDataError('symbol-key');
      out[key] = plainData(value[key], depth + 1);
    }
    return out;
  }
  throw new PlainDataError(`unsupported:${Object.prototype.toString.call(value).slice(8, -1)}`);
}
