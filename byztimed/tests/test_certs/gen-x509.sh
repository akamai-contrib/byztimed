#!/usr/bin/env bash
#Copyright 2020, Akamai Technologies, Inc.
#SPDX-License-Identifier: Apache-2.0

for node in alice bob charlie dave gorgias trent; do
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out ${node}.key
done

openssl req -new -subj "/CN=trent" -key trent.key -out trent.csr
openssl x509 -req -in trent.csr -signkey trent.key -out trent.crt -days 3650 -extfile openssl.cnf -extensions v3_ca

for node in alice bob charlie dave gorgias; do
    openssl req -new -subj "/CN=${node}" -key ${node}.key -out ${node}.csr
    openssl x509 -req -in ${node}.csr -CA trent.crt -CAkey trent.key \
            -CAcreateserial -out ${node}.crt -days 3650 \
            -extfile <(cat ./openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:${node}.test"))\
            -extensions SAN
done
