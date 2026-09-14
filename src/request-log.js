import { JsonStreamFormatter } from './json-format-stream.js';

// Streams one direction of a request log to disk; JSON is pretty-printed chunk by chunk.
export class BodyWriter {
  constructor(write, label, contentType) {
    this.write = write;
    this.label = label;
    this.isStream = /event-stream/.test(contentType);
    this.decided = false;
    this.fmt = null;
    this.headerWritten = false;
  }
  chunk(buf) {
    if (!buf.length) return;
    if (!this.headerWritten) { this.write(`\n\n=== ${this.label} ===\n`); this.headerWritten = true; }
    if (!this.decided) {
      const first = buf.toString('latin1').trimStart()[0];
      if (!this.isStream && (first === '{' || first === '[')) this.fmt = new JsonStreamFormatter();
      this.decided = true;
    }
    this.write(this.fmt ? this.fmt.push(buf) : buf.toString('latin1'));
  }
}
