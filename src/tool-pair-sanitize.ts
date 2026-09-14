// Removes tool_use / tool_result blocks whose counterpart is not in the adjacent
// message (upstream 400s on those). A valid body comes back as the same Buffer.

const MESSAGES_PATH = '/v1/messages';

// Neither substring present → nothing to prune, skip the parse.
const TOOL_USE_MARKER = Buffer.from('"tool_use"');
const TOOL_RESULT_MARKER = Buffer.from('"tool_result"');

interface ContentBlock {
  type?: string;
  id?: string;
  tool_use_id?: string;
  text?: string;
  [key: string]: any;
}

interface Message {
  role?: string;
  content?: string | ContentBlock[];
  [key: string]: any;
}

function isMessagesRequest(url: unknown, contentType: unknown): boolean {
  if (typeof url !== 'string' || !url.includes(MESSAGES_PATH)) return false;
  if (contentType && !/json/i.test(String(contentType))) return false;
  return true;
}

function toolUseIds(msg: Message | null | undefined): Set<string> {
  const ids = new Set<string>();
  if (msg && Array.isArray(msg.content)) {
    for (const b of msg.content) {
      if (b && typeof b === 'object' && b.type === 'tool_use' && typeof b.id === 'string') ids.add(b.id);
    }
  }
  return ids;
}

function toolResultIds(msg: Message | null | undefined): Set<string> {
  const ids = new Set<string>();
  if (msg && Array.isArray(msg.content)) {
    for (const b of msg.content) {
      if (b && typeof b === 'object' && b.type === 'tool_result' && typeof b.tool_use_id === 'string') ids.add(b.tool_use_id);
    }
  }
  return ids;
}

// Upstream treats a plain string and a single text block as equivalent.
function toBlocks(content: Message['content']): ContentBlock[] | null {
  if (Array.isArray(content)) return content;
  if (typeof content === 'string') return [{ type: 'text', text: content }];
  return null;
}

// Pruning can leave two same-role messages adjacent; upstream requires alternation.
function coalesceSameRole(messages: Message[]): Message[] {
  const out: Message[] = [];
  for (const msg of messages) {
    const prev = out[out.length - 1];
    if (prev && msg && prev.role && prev.role === msg.role) {
      const a = toBlocks(prev.content);
      const b = toBlocks(msg.content);
      if (a && b) {
        out[out.length - 1] = { ...prev, content: [...a, ...b] };
        continue;
      }
    }
    out.push(msg);
  }
  return out;
}

function pruneOnce(messages: Message[]): { messages: Message[]; changed: boolean } {
  let changed = false;

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i]!;
    if (!msg || !Array.isArray(msg.content)) continue;
    const answeredByNext = toolResultIds(messages[i + 1]);
    const groundedByPrev = toolUseIds(messages[i - 1]);
    const kept: ContentBlock[] = [];
    for (const b of msg.content) {
      if (b && typeof b === 'object') {
        if (b.type === 'tool_use' && typeof b.id === 'string' && !answeredByNext.has(b.id)) {
          changed = true;
          continue;
        }
        if (b.type === 'tool_result' && typeof b.tool_use_id === 'string' && !groundedByPrev.has(b.tool_use_id)) {
          changed = true;
          continue;
        }
      }
      kept.push(b);
    }
    if (kept.length !== msg.content.length) msg.content = kept;
  }

  let droppedAny = false;
  const kept: Message[] = [];
  for (const msg of messages) {
    if (msg && Array.isArray(msg.content) && msg.content.length === 0) {
      changed = true;
      droppedAny = true;
      continue;
    }
    kept.push(msg);
  }

  const result = droppedAny ? coalesceSameRole(kept) : kept;
  if (result.length !== kept.length) changed = true;
  return { messages: result, changed };
}

// To a fixed point: dropping a message shifts adjacency and can expose a new orphan.
function pruneOrphans(messages: Message[]): Message[] | null {
  let current = messages;
  let everChanged = false;
  for (let guard = 0; guard < 1000; guard++) {
    const { messages: next, changed } = pruneOnce(current);
    current = next;
    if (!changed) break;
    everChanged = true;
  }
  return everChanged ? current : null;
}

export function sanitizeToolPairs(body: Buffer, url: unknown, contentType: unknown): Buffer {
  if (!Buffer.isBuffer(body) || body.length === 0) return body;
  if (!isMessagesRequest(url, contentType)) return body;
  if (!body.includes(TOOL_USE_MARKER) && !body.includes(TOOL_RESULT_MARKER)) return body;

  let payload: { messages?: Message[] } | null;
  try {
    payload = JSON.parse(body.toString('utf8'));
  } catch {
    return body;
  }
  if (!payload || !Array.isArray(payload.messages)) return body;

  try {
    const pruned = pruneOrphans(payload.messages);
    if (!pruned) return body;
    payload.messages = pruned;
    return Buffer.from(JSON.stringify(payload), 'utf8');
  } catch {
    return body; // any surprise: forward the original untouched
  }
}
