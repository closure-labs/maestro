#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
umask 077

: "${MAESTRO_XO_TLS_CERT:?MAESTRO_XO_TLS_CERT must be set}"
: "${MAESTRO_XO_TLS_KEY:?MAESTRO_XO_TLS_KEY must be set}"
: "${MAESTRO_XO_TLS_DIR:?MAESTRO_XO_TLS_DIR must be set}"
: "${MAESTRO_XO_HOSTNAME:?MAESTRO_XO_HOSTNAME must be set}"
: "${MAESTRO_XO_HTTP_HOST:?MAESTRO_XO_HTTP_HOST must be set}"
: "${MAESTRO_XO_USER:?MAESTRO_XO_USER must be set}"
: "${MAESTRO_XO_GROUP:?MAESTRO_XO_GROUP must be set}"

mkdir -p "$MAESTRO_XO_TLS_DIR"
chmod 0755 "$MAESTRO_XO_TLS_DIR"

if [ -s "$MAESTRO_XO_TLS_KEY" ] \
  && [ -s "$MAESTRO_XO_TLS_CERT" ] \
  && openssl x509 -checkend 0 -noout -in "$MAESTRO_XO_TLS_CERT" 2>/dev/null
then
  exit 0
fi

openssl req \
  -x509 \
  -newkey rsa:4096 \
  -nodes \
  -days 3650 \
  -keyout "$MAESTRO_XO_TLS_KEY" \
  -out "$MAESTRO_XO_TLS_CERT" \
  -subj "/CN=$MAESTRO_XO_HOSTNAME" \
  -addext "subjectAltName=DNS:$MAESTRO_XO_HOSTNAME,DNS:localhost,IP:$MAESTRO_XO_HTTP_HOST"

chown "$MAESTRO_XO_USER:$MAESTRO_XO_GROUP" "$MAESTRO_XO_TLS_KEY" "$MAESTRO_XO_TLS_CERT"
chmod 0640 "$MAESTRO_XO_TLS_KEY" "$MAESTRO_XO_TLS_CERT"
