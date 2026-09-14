import { JsonStreamFormatter } from './json-format-stream.ts';

// Streams one direction of a request log to disk; JSON is pretty-printed chunk by chunk.
export class BodyWriter {
  write: (s: string) => void;
  label: string;
  isStream: boolean;
  decided = false;
  fmt: JsonStreamFormatter | null = null;
  headerWritten = false;

  constructor(write: (s: string) => void, label: string, contentType: string) {
    this.write = write;
    this.label = label;
    this.isStream = /event-stream/.test(contentType);
  }

  chunk(buf: Buffer): void {
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
