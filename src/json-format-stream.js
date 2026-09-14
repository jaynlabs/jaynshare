// Streaming JSON pretty-printer: one pass, no whole-body buffering. Works on
// latin1 so a UTF-8 sequence split across chunks survives byte-for-byte.
export class JsonStreamFormatter {
  constructor(indent = 2) {
    this.pad = ' '.repeat(indent);
    this.depth = 0;
    this.inStr = false;
    this.esc = false;
    this.freshContainer = false; // just opened { or [
  }

  newline(depth) { return '\n' + this.pad.repeat(depth); }

  push(buf) {
    const text = Buffer.isBuffer(buf) ? buf.toString('latin1') : String(buf);
    let out = '';
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];

      if (this.inStr) {
        out += ch;
        if (this.esc) this.esc = false;
        else if (ch === '\\') this.esc = true;
        else if (ch === '"') this.inStr = false;
        continue;
      }

      if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') continue;

      if (ch === '}' || ch === ']') {
        this.depth--;
        if (this.freshContainer) { this.freshContainer = false; out += ch; }
        else out += this.newline(this.depth) + ch;
        continue;
      }

      if (this.freshContainer) { out += this.newline(this.depth); this.freshContainer = false; }

      if (ch === '{' || ch === '[') { out += ch; this.depth++; this.freshContainer = true; continue; }
      if (ch === ',') { out += ',' + this.newline(this.depth); continue; }
      if (ch === ':') { out += ': '; continue; }
      if (ch === '"') { this.inStr = true; out += ch; continue; }
      out += ch;
    }
    return out;
  }
}
