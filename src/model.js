// Model-id helpers; dependency-free so the relay can peek a request's model.

export function isFableModel(model) {
  return typeof model === 'string' && /fable/i.test(model);
}

export function modelFamily(model) {
  if (typeof model !== 'string' || !model) return 'other';
  if (/fable/i.test(model)) return 'fable';
  if (/sonnet/i.test(model)) return 'sonnet';
  if (/opus/i.test(model)) return 'opus';
  if (/haiku/i.test(model)) return 'haiku';
  return 'other';
}

// Families metered by their own weekly bucket; the rest share 'unified7d'.
const FAMILY_WEEKLY_BUCKET = {
  fable: 'unified7dFable',
  sonnet: 'unified7dSonnet',
};

export function weeklyBucketForModel(model) {
  return FAMILY_WEEKLY_BUCKET[modelFamily(model)] || 'unified7d';
}

// Only `*` is special; case-insensitive.
export function modelGlobMatches(glob, model) {
  if (typeof glob !== 'string' || typeof model !== 'string') return false;
  const re = '^' + glob.split('*').map(escapeRegExp).join('.*') + '$';
  return new RegExp(re, 'i').test(model);
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Display-only approximation: two globs overlap when either literal core contains the other.
export function modelGlobOverlaps(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const core = s => s.replace(/\*/g, '').toLowerCase();
  const ca = core(a);
  const cb = core(b);
  return ca.includes(cb) || cb.includes(ca);
}

// Display-only: the blocklist pattern that covers a family, by glob or by substring.
export function findFamilyBlock(patterns, family) {
  if (!Array.isArray(patterns) || !family) return null;
  const key = String(family).toLowerCase();
  return patterns.find(p => typeof p === 'string'
    && (modelGlobMatches(p, key) || p.toLowerCase().includes(key))) || null;
}

// Streaming locator for a string field at depth 1 of the root object; a same-named
// key nested in conversation content never matches.
export class TopLevelFieldFinder {
  constructor(field) {
    this.field = field;
    this.isObj = [];                  // container stack: true=object, false=array
    this.awaitingKey = false;
    this.inStr = false;
    this.esc = false;
    this.readingKey = false;
    this.readingValue = false;
    this.curKey = null;
    this.buf = [];
    this.value = null;
    this.done = false;                // found, or the root object closed without it
  }

  push(chunk) {
    if (this.done) return this.value;
    for (let i = 0; i < chunk.length && !this.done; i++) this.#byte(chunk[i]);
    return this.value;
  }

  #atRoot() { return this.isObj.length === 1 && this.isObj[0] === true; }

  #byte(b) {
    if (this.inStr) {
      if (this.esc) { this.esc = false; if (this.readingKey || this.readingValue) this.buf.push(b); return; }
      if (b === 0x5c) { this.esc = true; if (this.readingKey || this.readingValue) this.buf.push(b); return; } // backslash
      if (b === 0x22) {                                            // closing quote
        this.inStr = false;
        if (this.readingKey) {
          this.curKey = Buffer.from(this.buf).toString('utf8'); this.buf = []; this.readingKey = false;
        } else if (this.readingValue) {
          this.value = Buffer.from(this.buf).toString('utf8'); this.buf = [];
          this.readingValue = false; this.done = true;
        }
        return;
      }
      if (this.readingKey || this.readingValue) this.buf.push(b);
      return;
    }

    switch (b) {
      case 0x7b: this.isObj.push(true); this.awaitingKey = true; this.curKey = null; break;   // {
      case 0x5b: this.isObj.push(false); this.awaitingKey = false; break;                     // [
      case 0x7d: case 0x5d:                                                                    // } ]
        this.isObj.pop(); this.curKey = null;
        if (this.isObj.length === 0) this.done = true;             // root closed → field absent
        break;
      case 0x3a: this.awaitingKey = false; break;                  // :
      case 0x2c: this.awaitingKey = this.isObj[this.isObj.length - 1] === true; break;        // ,
      case 0x22:                                                   // string begins
        if (this.awaitingKey && this.isObj[this.isObj.length - 1]) {
          this.readingKey = true; this.buf = [];
        } else if (this.#atRoot() && this.curKey === this.field) {
          this.readingValue = true; this.buf = [];
        }
        this.inStr = true; this.esc = false;
        break;
      default: break;                                              // scalars / whitespace
    }
  }
}

export function parseRequestModel(body) {
  if (!body) return null;
  try {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
    return new TopLevelFieldFinder('model').push(buf);
  } catch { return null; }
}

// Streaming locator for the advisor tool's `model` — the second model an advisor
// request carries: `tools: [{ type: "advisor_…", model }]` directly under the root.
export class AdvisorModelFinder {
  constructor() {
    this.stack = [];                  // { isObj, key, awaitingKey }
    this.inStr = false;
    this.esc = false;
    this.reading = null;              // 'key' | 'type' | 'model' while in a string
    this.buf = [];
    this.toolType = null;
    this.toolModel = null;
    this.value = null;
    this.done = false;
  }

  push(chunk) {
    if (this.done) return this.value;
    for (let i = 0; i < chunk.length && !this.done; i++) this.#byte(chunk[i]);
    return this.value;
  }

  #inToolElement() {
    const s = this.stack;
    return s.length === 3 && s[0].isObj && s[0].key === 'tools' && !s[1].isObj && s[2].isObj;
  }

  #byte(b) {
    if (this.inStr) {
      if (this.esc) { this.esc = false; if (this.reading) this.buf.push(b); return; }
      if (b === 0x5c) { this.esc = true; if (this.reading) this.buf.push(b); return; } // backslash
      if (b === 0x22) {                                            // closing quote
        this.inStr = false;
        if (this.reading) {
          const text = Buffer.from(this.buf).toString('utf8');
          if (this.reading === 'key') this.stack[this.stack.length - 1].key = text;
          else if (this.reading === 'type') this.toolType = text;
          else this.toolModel = text;
          this.reading = null;
          this.buf = [];
        }
        return;
      }
      if (this.reading) this.buf.push(b);
      return;
    }

    switch (b) {
      case 0x7b:                                                   // {
        this.stack.push({ isObj: true, key: null, awaitingKey: true });
        if (this.#inToolElement()) { this.toolType = null; this.toolModel = null; }
        break;
      case 0x5b: this.stack.push({ isObj: false, key: null, awaitingKey: false }); break; // [
      case 0x7d:                                                   // }
        if (this.#inToolElement()
            && typeof this.toolType === 'string' && /^advisor/i.test(this.toolType)
            && this.toolModel) {
          this.value = this.toolModel;
          this.done = true;
        }
        // fall through: pop like ]
      case 0x5d:                                                   // ]
        this.stack.pop();
        if (this.stack.length === 0) this.done = true;             // root closed → absent
        break;
      case 0x3a: { const t = this.stack[this.stack.length - 1]; if (t?.isObj) t.awaitingKey = false; break; } // :
      case 0x2c: { const t = this.stack[this.stack.length - 1]; if (t?.isObj) t.awaitingKey = true; break; }  // ,
      case 0x22: {                                                 // string begins
        const t = this.stack[this.stack.length - 1];
        if (t?.isObj && t.awaitingKey) this.reading = 'key';
        else if (this.#inToolElement() && (t.key === 'type' || t.key === 'model')) this.reading = t.key;
        else this.reading = null;
        this.buf = [];
        this.inStr = true;
        this.esc = false;
        break;
      }
      default: break;                                              // scalars / whitespace
    }
  }
}

export function parseAdvisorModel(body) {
  if (!body) return null;
  try {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
    if (!buf.includes('advisor')) return null; // cheap gate before the structural scan
    return new AdvisorModelFinder().push(buf);
  } catch { return null; }
}
