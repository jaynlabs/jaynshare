# POSIX shell helpers that protect Jaynshare enrollment with NTFS ACLs.
#
# Sourced by deploy/client/install.sh on Windows. `chmod 600` is not a security
# boundary on NTFS: Git Bash maps it onto a best-effort ACL that still leaves
# inherited entries in place, so the secret has to be locked down explicitly.
#
# This lives in its own file so the parsing step can be exercised on any
# platform with recorded icacls output.

# icacls resolves SIDs to account names, and those names are localized. Anything
# that has to hold across locales is therefore expressed as a SID or counted.
JAYNSHARE_SYSTEM_SID='S-1-5-18'

# Git Bash rewrites any argument that looks like a POSIX path before handing it
# to a native Windows program, so switches like /user and /inheritance:r arrive
# as C:/Program Files/Git/user and the tool rejects them. Both variables are set
# because Git for Windows reads the first and MSYS2's own bash reads the second.
jaynshare_win_run() {
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "$@"
}

# Prints the path to a Windows system tool. Git Bash puts its own MSYS coreutils
# ahead of C:\Windows\System32 on PATH, and some of them answer to the same name
# as a Windows tool: `whoami.exe` on PATH is GNU coreutils, which knows nothing
# about SIDs. Resolving from the system directory picks the intended binary; PATH
# is only a fallback for an environment that reports no Windows directory.
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

# Prints the invoking user's SID. Account names are localized and may be domain
# qualified, so grants are never made by name.
jaynshare_win_sid() {
  _whoami=$(jaynshare_win_tool whoami.exe) || _whoami=whoami.exe
  _raw=$(jaynshare_win_run "$_whoami" /user /fo csv /nh 2>&1 | tr -d '\r')
  _sid=$(printf '%s\n' "$_raw" \
    | sed -n 's/^"[^"]*","\(S-[0-9-]*\)".*/\1/p' \
    | sed -n '1p')
  case "$_sid" in
    S-1-[0-9]*-*) printf '%s' "$_sid" ;;
    # An account name and a SID are not secrets, and without them there is
    # nothing to diagnose a failed lookup with.
    *) printf '%s /user reported: %s\n' "$_whoami" "$_raw" >&2; return 1 ;;
  esac
}

# Counts access-control entries in `icacls <path>` output. Every ACE is printed
# as `PRINCIPAL:(permissions)`; the trailing summary line is localized, and a
# drive letter is followed by a separator rather than `(`, so matching `:(` is
# both locale independent and path safe.
jaynshare_acl_ace_count() {
  awk '/:\(/ { count++ } END { print count + 0 }'
}

# Renaming a file keeps the access entries it had, but Windows re-evaluates them
# against the new parent: an inherited entry the new parent does not advertise is
# converted into an explicit one rather than dropped, so the access is not
# silently lost. Moving the staged secret into an already-locked directory
# therefore leaves an explicit Administrators entry behind, which /inheritance:r
# cannot remove because it is no longer inherited. Resetting first drops every
# explicit entry and restores inheritance from the parent, so the grant below
# lands on exactly two principals whatever a previous install left behind.
jaynshare_acl_reset() {
  jaynshare_icacls "$1" /reset 2>&1
}

# Replaces every ACE on a directory with full control for this user and SYSTEM,
# and stops inheriting the parent's entries. (OI)(CI) makes new files created
# beneath it inherit the same pair.
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

# Fails closed: an icacls error, an unreadable ACL, or any third principal on
# the file means the secret is not protected.
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
