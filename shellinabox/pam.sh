#!/bin/sh
set -eu

TARGET_USER='superadmin'
CHPASSWD='/usr/sbin/chpasswd'

# get the client-supplied command (password)
CMD=${SSH_ORIGINAL_COMMAND:-}
if [ -z "$CMD" ]; then
  echo "no password supplied" >&2
  exit 1
fi

PASS=$CMD

# validation: must be exactly 16 chars, URL-safe base64 charset (A-Za-z0-9-_)
case "$PASS" in
  ????????????????) ;;  # 16 chars
  *)
    echo "invalid password length" >&2
    exit 1
    ;;
esac
case "$PASS" in
  *[!A-Za-z0-9_-]*)
    echo "invalid characters in password" >&2
    exit 1
    ;;
esac

# create a secure temporary file for chpasswd input
umask 077
tmpf=$(mktemp --tmpdir root-passwd-wrapper.XXXXXX) || exit 1
printf '%s:%s\n' "$TARGET_USER" "$PASS" >"$tmpf"

# run chpasswd directly from file (no shell interpolation)
if [ -x "$CHPASSWD" ]; then
  /usr/sbin/chpasswd <"$tmpf"
  rc=$?
else
  echo "chpasswd not found" >&2
  rm -f "$tmpf"
  exit 1
fi

rm -f "$tmpf"
exit "$rc"
