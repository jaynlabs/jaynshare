const OSC_TITLE = '\x1b]0;';
const BEL = '\x07';

// xterm title stack; a no-op on terminals without it.
export const TITLE_STACK_PUSH = '\x1b[22;2t';
export const TITLE_STACK_POP = '\x1b[23;2t';

function truncate(s, max) {
  s = String(s);
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

export function formatTerminalTitle({ index = 0, total = 0, name = null } = {}) {
  const pos = total > 0 ? `${index + 1}/${total}` : '0/0';
  const who = name ? ` ${truncate(name, 24)}` : '';
  return `◆ jaynshare ${pos}${who}`;
}

export function titleSequence(title) {
  const safe = String(title).replace(/[\x00-\x1f\x7f]/g, ' ').trimEnd(); // an account name must not escape the sequence
  return `${OSC_TITLE}${safe}${BEL}`;
}
