#!/bin/sh
set -eu
export LC_ALL=C LANG=C

SINCE_EPOCH="${1:-${LOGIN_SINCE_EPOCH:-}}"
LAST_LINES="${2:-${LOGIN_LAST_LINES:-50}}"
case "$LAST_LINES" in
  ''|*[!0-9]*) LAST_LINES=50 ;;
esac
if [ "$LAST_LINES" -le 0 ]; then
  LAST_LINES=50
fi
case "$SINCE_EPOCH" in
  ''|*[!0-9]*) SINCE_EPOCH='' ;;
esac

# Capture the target clock before reading wtmp, so the next window also
# covers logins written while this probe is running.
server_epoch="$(date +%s 2>/dev/null)" || server_epoch=''
case "$server_epoch" in
  ''|*[!0-9]*) server_epoch='' ;;
esac

client_ip="${SSH_CONNECTION:-}"
printf 'self_ip=%s\n' "${client_ip%% *}"

if ! command -v last >/dev/null 2>&1; then
  printf 'logins_unavailable=1\n'
  exit 0
fi

if [ -d /dev/shm ]; then
  tmpdir="$(mktemp -d -p /dev/shm 2>/dev/null)" || tmpdir="$(mktemp -d)"
else
  tmpdir="$(mktemp -d)"
fi
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

raw="$tmpdir/raw"

emit_logins() {
  awk '
    $1 == "reboot" || $1 == "shutdown" || $1 == "crash" ||
    $1 == "wtmp" || $1 == "btmp" { next }
    NF < 8 { next }
    {
      user = $1; tty = $2; ip = $3
      if (ip !~ /[.:]/) next
      # `last -F` prints a 5-field start time ending in the year; the short
      # fallback format ends at $7 and $8 is the session status instead.
      if ($8 ~ /^[0-9]+$/) start = $4 " " $5 " " $6 " " $7 " " $8
      else start = $4 " " $5 " " $6 " " $7
      printf "login|%s|%s|%s|%s\n", user, tty, ip, start
    }
  ' "$1"
}

probe_last() {
  : > "$raw"
  last "$@" > "$raw" 2>/dev/null || return 1
  return 0
}

ran=0
if [ -n "$SINCE_EPOCH" ]; then
  if probe_last -F -n "$LAST_LINES" -i -s "@$SINCE_EPOCH"; then
    ran=1
  fi
fi

# Dropping -s must not also change the timestamp format used for deduplication.
if [ "$ran" -eq 0 ] && [ ! -s "$raw" ]; then
  if probe_last -F -n "$LAST_LINES" -i; then
    ran=1
  fi
fi

if [ "$ran" -eq 0 ] && [ ! -s "$raw" ]; then
  if probe_last -n "$LAST_LINES" -i; then
    ran=1
  fi
fi
if [ "$ran" -eq 0 ] && [ ! -s "$raw" ]; then
  if probe_last -n "$LAST_LINES"; then
    ran=1
  fi
fi

if [ "$ran" -eq 0 ] && [ ! -s "$raw" ]; then
  printf 'logins_unavailable=1\n'
  exit 0
fi

emit_logins "$raw"
printf 'server_epoch=%s\n' "$server_epoch"
exit 0
