#!/bin/sh
set -e

# Start sshd
exec /usr/sbin/sshd &

# Start shellinaboxd in foreground
exec shellinaboxd --port=${SHELLINABOX_PORT} ${SHELLINABOX_OPTIONS} --user=superadmin --group=superadmin
