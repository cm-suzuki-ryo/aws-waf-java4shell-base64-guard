#!/usr/bin/env bash
# Send harmless test requests to a test ALB you own and print the HTTP status.
# Usage: bash test/curl_checks.sh <alb-dns-name>
# The malformed token is only a string here. Do not point this at a real Java
# service that decodes Base64 on an AVX-512 VBMI host without -XX:-UseBASE64Intrinsics.
set -u
HOST="${1:?usage: curl_checks.sh <alb-dns-name>}"
URL="http://${HOST}/"
BAD="$(printf 'A%.0s' {1..64})="          # 64 x A + "=" : malformed
BAD_SHORT="$(printf 'A%.0s' {1..20})="     # 20 x A + "=" : below the 32 char floor
VALID="$(printf 'A%.0s' {1..34})=="        # 36 chars, valid padding

req() {
  local name="$1"; shift
  local code
  code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$@")"
  printf '%-34s %s\n' "$name" "$code"
}

req "get (no token)"                   "$URL"
req "auth: malformed (expect count)"   -H "Authorization: Basic ${BAD}" "$URL"
req "cookie: malformed (expect count)" -H "Cookie: session=${BAD}" "$URL"
req "query: malformed (expect count)"  "${URL}?t=${BAD}"
req "query: url-encoded =  (count)"    "${URL}?t=$(printf 'A%.0s' {1..64})%3D"
req "body: malformed (expect count)"   -X POST -H 'Content-Type: text/plain' --data "token=${BAD}" "$URL"
req "auth: valid basic (no count)"     -u user:pass "$URL"
req "auth: valid padded 36 (no count)" -H "Authorization: Basic ${VALID}" "$URL"
req "auth: short malformed (no count)" -H "Authorization: Basic ${BAD_SHORT}" "$URL"
req "cookie: jwt-like (no count)"      -H "Cookie: jwt=eyJhbGciOiJIUzI1NiJ9.$(printf 'e%.0s' {1..40}).$(printf 's%.0s' {1..43})" "$URL"
