// Model-id helpers; dependency-free so the relay can peek a request's model.

export function isFableModel(model: unknown): boolean {
  return typeof model === 'string' && /fable/i.test(model);
}

export function modelFamily(model: unknown): string {
  if (typeof model !== 'string' || !model) return 'other';
  if (/fable/i.test(model)) return 'fable';
  if (/sonnet/i.test(model)) return 'sonnet';
  if (/opus/i.test(model)) return 'opus';
  if (/haiku/i.test(model)) return 'haiku';
  return 'other';
}

// Families metered by their own weekly bucket; the rest share 'unified7d'.
const FAMILY_WEEKLY_BUCKET: Record<string, string> = {
  fable: 'unified7dFable',
  sonnet: 'unified7dSonnet',
};

export function weeklyBucketForModel(model: unknown): string {
  return FAMILY_WEEKLY_BUCKET[modelFamily(model)] || 'unified7d';
}

// Only `*` is special; case-insensitive.
export function modelGlobMatches(glob: unknown, model: unknown): boolean {
  if (typeof glob !== 'string' || typeof model !== 'string') return false;
  const re = '^' + glob.split('*').map(escapeRegExp).join('.*') + '$';
  return new RegExp(re, 'i').test(model);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Display-only approximation: two globs overlap when either literal core contains the other.
export function modelGlobOverlaps(globA: unknown, globB: unknown): boolean {
  if (typeof globA !== 'string' || typeof globB !== 'string') return false;
  const core = (text: string) => text.replace(/\*/g, '').toLowerCase();
  const coreA = core(globA);
  const coreB = core(globB);
  return coreA.includes(coreB) || coreB.includes(coreA);
}

// Display-only: the blocklist pattern that covers a family, by glob or by substring.
export function findFamilyBlock(patterns: unknown, family: unknown): string | null {
  if (!Array.isArray(patterns) || !family) return null;
  const key = String(family).toLowerCase();
  return (patterns as unknown[]).find(p => typeof p === 'string'
    && (modelGlobMatches(p, key) || p.toLowerCase().includes(key))) as string | null || null;
}

function* toByteIterable(chunk: Buffer | string): IterableIterator<number> {
  if (typeof chunk === 'string') {
    for (let i = 0; i < chunk.length; i++) yield chunk.charCodeAt(i);
  } else {
    for (let i = 0; i < chunk.length; i++) yield chunk[i]!;
  }
}

// Streaming locator for a string field at depth 1 of the root object; a same-named
// key nested in conversation content never matches.
export class TopLevelFieldFinder {
  field: string;
  isObj: boolean[] = [];              // container stack: true=object, false=array
  awaitingKey = false;
  inStr = false;
  esc = false;
  readingKey = false;
  readingValue = false;
  curKey: string | null = null;
  buf: number[] = [];
  value: string | null = null;
  done = false;                       // found, or the root object closed without it

  constructor(field: string) {
    this.field = field;
  }

  push(chunk: Buffer | string): string | null {
    if (this.done) return this.value;
    const bytes = toByteIterable(chunk);
    for (const b of bytes) { if (this.done) break; this.#byte(b); }
    return this.value;
  }

  #atRoot(): boolean { return this.isObj.length === 1 && this.isObj[0] === true; }

  #byte(b: number): void {
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

export function parseRequestModel(body: Buffer | string | null | undefined): string | null {
  if (!body) return null;
  try {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
    return new TopLevelFieldFinder('model').push(buf);
  } catch { return null; }
}

interface Frame {
  isObj: boolean;
  key: string | null;
  awaitingKey: boolean;
}

// Streaming locator for the advisor tool's `model` — the second model an advisor
// request carries: `tools: [{ type: "advisor_…", model }]` directly under the root.
export class AdvisorModelFinder {
  stack: Frame[] = [];              // { isObj, key, awaitingKey }
  inStr = false;
  esc = false;
  reading: 'key' | 'type' | 'model' | null = null; // while in a string
  buf: number[] = [];
  toolType: string | null = null;
  toolModel: string | null = null;
  value: string | null = null;
  done = false;

  push(chunk: Buffer | string): string | null {
    if (this.done) return this.value;
    const bytes = toByteIterable(chunk);
    for (const b of bytes) { if (this.done) break; this.#byte(b); }
    return this.value;
  }

  #inToolElement(): boolean {
    const s = this.stack;
    return s.length === 3 && s[0]!.isObj && s[0]!.key === 'tools' && !s[1]!.isObj && s[2]!.isObj;
  }

  #byte(b: number): void {
    if (this.inStr) {
      if (this.esc) { this.esc = false; if (this.reading) this.buf.push(b); return; }
      if (b === 0x5c) { this.esc = true; if (this.reading) this.buf.push(b); return; } // backslash
      if (b === 0x22) {                                            // closing quote
        this.inStr = false;
        if (this.reading) {
          const text = Buffer.from(this.buf).toString('utf8');
          if (this.reading === 'key') this.stack[this.stack.length - 1]!.key = text;
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
          break;
        }
        this.stack.pop();                                          // pop like ]
        if (this.stack.length === 0) this.done = true;             // root closed → absent
        break;
      case 0x3a: { const t = this.stack[this.stack.length - 1]; if (t?.isObj) t.awaitingKey = false; break; } // :
      case 0x2c: { const t = this.stack[this.stack.length - 1]; if (t?.isObj) t.awaitingKey = true; break; }  // ,
      case 0x22: {                                                 // string begins
        const t = this.stack[this.stack.length - 1];
        if (t?.isObj && t.awaitingKey) this.reading = 'key';
        else if (this.#inToolElement() && (t.key === 'type' || t.key === 'model')) this.reading = t.key as 'type' | 'model';
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

export function parseAdvisorModel(body: Buffer | string | null | undefined): string | null {
  if (!body) return null;
  try {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
    if (!buf.includes('advisor')) return null; // cheap gate before the structural scan
    return new AdvisorModelFinder().push(buf);
  } catch { return null; }
}
