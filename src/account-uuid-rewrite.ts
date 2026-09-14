// Streaming rewrite of the `account_uuid` in `metadata.user_id` to the injected
// account's; same length in, same length out.

// `account_uuid":"` as it appears escaped inside the user_id string.
const PREFIX = Buffer.from('account_uuid\\":\\"', 'latin1');

interface UuidFrame {
  container: 'obj' | 'arr';
  name: string | null;
  key: string | null;
  awaitingKey: boolean;
}

export class AccountUuidPatcher {
  newUuid: Buffer | null;
  frames: UuidFrame[] = [];  // { container: 'obj'|'arr', name, key, awaitingKey }
  inStr = false;
  esc = false;
  readingKey = false;
  keyBuf: number[] = [];
  target = false;            // inside the metadata.user_id string
  matchPos = 0;              // PREFIX bytes matched so far
  uuidRemaining = 0;         // value bytes left to overwrite
  done = false;
  changed = false;

  constructor(newUuid: string) {
    this.newUuid = (typeof newUuid === 'string' && newUuid.length === 36) ? Buffer.from(newUuid, 'latin1') : null;
  }

  push(chunk: Buffer): Buffer {
    if (!this.newUuid || this.done) return chunk;
    const out = Buffer.from(chunk);
    for (let i = 0; i < out.length; i++) {
      out[i] = this.#byte(out[i]!);
      if (this.done) break;
    }
    return out;
  }

  #top(): UuidFrame | undefined { return this.frames[this.frames.length - 1]; }

  #byte(b: number): number {
    if (this.target) return this.#targetByte(b);

    if (this.inStr) {
      if (this.esc) { this.esc = false; if (this.readingKey) this.keyBuf.push(b); return b; }
      if (b === 0x5c) { this.esc = true; return b; }             // backslash
      if (b === 0x22) {                                          // end of string
        this.inStr = false;
        if (this.readingKey) { this.#top()!.key = Buffer.from(this.keyBuf).toString('latin1'); this.keyBuf = []; this.readingKey = false; }
        return b;
      }
      if (this.readingKey) this.keyBuf.push(b);
      return b;
    }

    const top = this.#top();
    switch (b) {
      case 0x7b: this.frames.push({ container: 'obj', name: top ? top.key : null, key: null, awaitingKey: true }); break; // {
      case 0x5b: this.frames.push({ container: 'arr', name: top ? top.key : null, key: null, awaitingKey: false }); break; // [
      case 0x7d: case 0x5d: this.frames.pop(); break;            // } ]
      case 0x3a: if (top) top.awaitingKey = false; break;        // : (key → value)
      case 0x2c: if (top && top.container === 'obj') top.awaitingKey = true; break; // ,
      case 0x22:                                                 // string start
        if (top && top.container === 'obj' && top.awaitingKey) {
          this.readingKey = true; this.keyBuf = []; this.inStr = true; this.esc = false;
        } else {
          this.inStr = true; this.esc = false; this.readingKey = false;
          if (top && top.container === 'obj' && top.name === 'metadata' && top.key === 'user_id' && this.frames.length === 2) {
            this.target = true; this.matchPos = 0; this.uuidRemaining = 0;
          }
        }
        break;
      default: break; // scalars / whitespace
    }
    return b;
  }

  #targetByte(b: number): number {
    if (this.uuidRemaining > 0) {
      const outByte = this.newUuid![this.newUuid!.length - this.uuidRemaining]!;
      this.uuidRemaining--;
      if (outByte !== b) this.changed = true;
      if (this.uuidRemaining === 0) this.done = true;
      return outByte;
    }
    if (this.esc) { this.esc = false; this.#match(b); return b; }
    if (b === 0x5c) { this.esc = true; this.#match(b); return b; }
    if (b === 0x22) { this.target = false; this.matchPos = 0; return b; } // end of user_id value
    this.#match(b);
    return b;
  }

  #match(b: number): void {
    if (b === PREFIX[this.matchPos]) {
      this.matchPos++;
      if (this.matchPos === PREFIX.length) { this.uuidRemaining = 36; this.matchPos = 0; }
    } else {
      this.matchPos = (b === PREFIX[0]) ? 1 : 0; // PREFIX has no internal repeat of its first byte
    }
  }
}

export function patchAccountUuid(buf: Buffer, newUuid: string): Buffer {
  const patcher = new AccountUuidPatcher(newUuid);
  const out = patcher.push(buf);
  return patcher.changed ? out : buf;
}
