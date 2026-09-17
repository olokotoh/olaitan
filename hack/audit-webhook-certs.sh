#!/usr/bin/env bash
# Story 10.8 (#137 B3). Produce the mTLS material the audit webhook
# needs, in one place, so both sides of the handshake agree.
#
# The receiver verifies the apiserver's CLIENT certificate against
# auditWebhook.clusterCAData (internal/collector/audit/audit.go,
# ClientCAs) and additionally pins its CN. AUDIT.md used to sign the
# client cert with a private audit CA while telling the operator to set
# clusterCAData to the cluster's own root CA, so the receiver rejected
# every apiserver connection. One CA signs both certificates here, and
# that CA is what clusterCAData carries.
#
# Usage:
#   hack/audit-webhook-certs.sh <out-dir> [server-name ...]
#
# Each server name is added to the receiver's serving certificate: a DNS
# name (the Service FQDN), an IPv4 address (127.0.0.1 when the receiver
# is published on the node through auditWebhook.hostPort) or an IPv6
# address, bare or bracketed. With none given, the defaults for release
# "olaitan" in namespace "olaitan" are used.
#
# It writes, all readable by the owner only:
#   audit-ca.crt, audit-ca.key, audit-ca.srl    the CA (keep the key offline)
#   audit-server.crt, audit-server.key          the receiver's serving pair
#   audit-client.crt, audit-client.key          the apiserver's client pair
#   audit-webhook-values.yaml                   every field base64-encoded
#                                               on one line, ready for
#                                               `helm install -f`
#
# It refuses to run into a directory that already holds a CA, so a second
# run cannot silently replace the CA every existing certificate chains to.
set -euo pipefail

# Every output is key material or embeds it.
umask 077

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <out-dir> [server-name ...]" >&2
    exit 2
fi

die() {
    echo "$0: $*" >&2
    exit 2
}

out_dir="$1"
shift
names=("$@")
if [ "${#names[@]}" -eq 0 ]; then
    names=("olaitan-audit-webhook.olaitan.svc.cluster.local" "olaitan-audit-webhook.olaitan.svc" "127.0.0.1")
fi

# CN the receiver pins on the apiserver's client certificate. It must be
# one the receiver allows: audit.Config.ClientCNAllow in
# internal/collector/audit/audit.go, which defaults to kube-apiserver and
# is not exposed as a chart value.
client_cn="${AUDIT_CLIENT_CN:-kube-apiserver}"
days="${AUDIT_CERT_DAYS:-365}"

# Validate everything before writing anything.
if ! printf '%s' "$client_cn" | grep -Eq '^[A-Za-z0-9._-]+$'; then
    die "AUDIT_CLIENT_CN is \"${client_cn}\": want letters, digits, '.', '_' or '-' only."
fi
if ! printf '%s' "$days" | grep -Eq '^[1-9][0-9]*$'; then
    die "AUDIT_CERT_DAYS is \"${days}\": want a positive whole number of days."
fi

san=""
for n in "${names[@]}"; do
    if [ -z "$n" ]; then
        die "empty server name: every name must be a DNS name or an IP address."
    fi
    if printf '%s' "$n" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
        IFS=. read -r o1 o2 o3 o4 <<<"$n"
        for o in "$o1" "$o2" "$o3" "$o4"; do
            if [ "${#o}" -gt 3 ] || [ "$((10#$o))" -gt 255 ]; then
                die "server name ${n} is not an IPv4 address: octet ${o} is not 0-255."
            fi
        done
        san="${san}${san:+,}IP:${n}"
    elif printf '%s' "$n" | grep -q ':'; then
        # IPv6, as written in serverAddress ([fd00::1]) or bare.
        ip="${n#\[}"
        ip="${ip%\]}"
        if ! printf '%s' "$ip" | grep -Eq '^[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*$'; then
            die "server name ${n} is not an IPv6 address."
        fi
        san="${san}${san:+,}IP:${ip}"
    elif printf '%s' "$n" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'; then
        san="${san}${san:+,}DNS:${n}"
    else
        die "server name ${n} is not a DNS name or an IP address."
    fi
done

if [ -e "${out_dir}/audit-ca.key" ] || [ -e "${out_dir}/audit-ca.crt" ]; then
    die "${out_dir} already holds an audit CA (audit-ca.crt or audit-ca.key). A new CA would orphan every certificate the old one signed. Use an empty directory, or move the old CA away first."
fi

mkdir -p "$out_dir"
cd "$out_dir"

# One CA for both directions. RSA for broad compatibility. The CA
# extensions are explicit rather than left to the local openssl.cnf.
cat > audit-ca.cnf <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = olaitan-audit-ca
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
    -config audit-ca.cnf -keyout audit-ca.key -out audit-ca.crt

# Receiver serving certificate, with a SAN for every address the
# apiserver may dial (auditWebhook.serverAddress).
openssl req -newkey rsa:2048 -nodes -subj "/CN=olaitan-audit-webhook" \
    -keyout audit-server.key -out audit-server.csr
printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$san" > audit-server.ext
openssl x509 -req -in audit-server.csr -CA audit-ca.crt -CAkey audit-ca.key \
    -CAcreateserial -days "$days" -extfile audit-server.ext -out audit-server.crt

# The apiserver's client certificate, signed by the SAME CA the receiver
# verifies clients against, with the CN the receiver pins.
openssl req -newkey rsa:2048 -nodes -subj "/CN=${client_cn}" \
    -keyout audit-client.key -out audit-client.csr
printf 'extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n' > audit-client.ext
openssl x509 -req -in audit-client.csr -CA audit-ca.crt -CAkey audit-ca.key \
    -CAcreateserial -days "$days" -extfile audit-client.ext -out audit-client.crt

# One line of base64 on GNU and BSD alike (BSD base64 has no -w0).
b64() { base64 < "$1" | tr -d '\n'; }

cat > audit-webhook-values.yaml <<EOF
# Generated by hack/audit-webhook-certs.sh. Pass with: helm install -f
# this file. caBundle is the CA the apiserver trusts for the receiver's
# serving cert; clusterCAData is the CA the receiver verifies the
# apiserver's client cert against. Story 10.8: they are the same CA, and
# the client cert below is signed by it.
auditWebhook:
  enabled: true
  caBundle: "$(b64 audit-ca.crt)"
  clusterCAData: "$(b64 audit-ca.crt)"
  servingCert: "$(b64 audit-server.crt)"
  servingKey: "$(b64 audit-server.key)"
  apiserverClientCert: "$(b64 audit-client.crt)"
  apiserverClientKey: "$(b64 audit-client.key)"
EOF

rm -f audit-ca.cnf audit-server.csr audit-client.csr audit-server.ext audit-client.ext

echo "wrote $(pwd)/audit-webhook-values.yaml"
echo "serving-cert names: ${names[*]}"
echo "client CN: ${client_cn}"
echo "audit-ca.key can sign certificates the receiver trusts: move it offline or delete it once the values are installed."
