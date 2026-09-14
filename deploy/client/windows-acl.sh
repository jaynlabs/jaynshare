# NTFS ACL helpers for the enrollment files: on NTFS `chmod 600` leaves inherited entries in place.

# Account names are localized, so everything is expressed as a SID or counted.
JAYNSHARE_SYSTEM_SID='S-1-5-18'

# Git Bash would rewrite /user and /inheritance:r into paths.
jaynshare_win_run() {
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "$@"
}

# Git Bash puts its own coreutils ahead of System32 on PATH: its whoami.exe knows nothing about SIDs.
jaynshare_win_tool() {
  for _root in "${SYSTEMROOT:-}" "${WINDIR:-}"
  do
    [ -n "$_root" ] || continue
    _sys=$(cygpath -u -- "$_root" 2>/dev/null | tr -d '\r')
    [ -n "$_sys" ] && [ -x "$_sys/System32/$1" ] || continue
    printf '%s' "$_sys/System32/$1"
    return 0
  done
  command -v "$1" 2>/dev/null
}

jaynshare_icacls() {
  _icacls=$(jaynshare_win_tool icacls.exe) \
    || _icacls=$(jaynshare_win_tool icacls) \
    || _icacls=icacls
  jaynshare_win_run "$_icacls" "$@"
}

jaynshare_cygpath() {
  cygpath -w -- "$1" | tr -d '\r'
}

jaynshare_win_sid() {
  _whoami=$(jaynshare_win_tool whoami.exe) || _whoami=whoami.exe
  _raw=$(jaynshare_win_run "$_whoami" /user /fo csv /nh 2>&1 | tr -d '\r')
  _sid=$(printf '%s\n' "$_raw" \
    | sed -n 's/^"[^"]*","\(S-[0-9-]*\)".*/\1/p' \
    | sed -n '1p')
  case "$_sid" in
    S-1-[0-9]*-*) printf '%s' "$_sid" ;;
    *) printf '%s /user reported: %s\n' "$_whoami" "$_raw" >&2; return 1 ;;
  esac
}

# Every ACE prints as `PRINCIPAL:(permissions)`; the summary line is localized.
jaynshare_acl_ace_count() {
  awk '/:\(/ { count++ } END { print count + 0 }'
}

# A move converts inherited entries into explicit ones, which /inheritance:r cannot remove.
jaynshare_acl_reset() {
  jaynshare_icacls "$1" /reset 2>&1
}

# (OI)(CI): new files beneath inherit the same pair.
jaynshare_lock_dir() {
  _win=$(jaynshare_cygpath "$2")
  _reset=$(jaynshare_acl_reset "$_win") || { printf '%s\n' "$_reset"; return 1; }
  jaynshare_icacls "$_win" /inheritance:r \
    /grant:r "*$1:(OI)(CI)F" "*$JAYNSHARE_SYSTEM_SID:(OI)(CI)F" 2>&1
}

jaynshare_lock_file() {
  _win=$(jaynshare_cygpath "$2")
  _reset=$(jaynshare_acl_reset "$_win") || { printf '%s\n' "$_reset"; return 1; }
  jaynshare_icacls "$_win" /inheritance:r \
    /grant:r "*$1:F" "*$JAYNSHARE_SYSTEM_SID:F" 2>&1
}

# Fails closed.
jaynshare_verify_locked() {
  _acl=$(jaynshare_icacls "$(jaynshare_cygpath "$1")" 2>&1) || {
    printf '%s\n' "$_acl"
    return 1
  }
  _count=$(printf '%s\n' "$_acl" | jaynshare_acl_ace_count)
  [ "$_count" = 2 ] || {
    printf '%s\n' "expected exactly 2 access entries, found $_count:"
    printf '%s\n' "$_acl"
    return 1
  }
}
