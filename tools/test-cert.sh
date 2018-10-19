#!/bin/sh
set -eux
T="$(mktemp)"

trap "rm ${T}" EXIT

cat >$T <<E
[req]
distinguished_name=dn
[ dn ]
CN=localhost
[ ext ]
basicConstraints=CA:FALSE,pathlen:0
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
E

cat $T

openssl req \
    -nodes \
    -x509 \
    -newkey rsa:2048 \
    -config "$T" \
    -extensions ext \
    -subj /C=GB/L=Snake/O=Oil/CN=localhost \
    -keyout localhost.key -out localhost.crt \
    -days 365
