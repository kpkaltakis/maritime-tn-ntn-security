#!/bin/bash
# s2_issue.sh -- run ON VM-11 (pki-ca). Issues a PQC LEAF cert under the existing
# RSA CA (Option 1: classical root + PQC leaf = the real migration story).
# Args: $1 = vessel id (e.g. athena), $2 = pqc alg (mldsa44 | falcon512 | falconpadded512)
# Writes to /tmp/triton_cred/<vessel> so it does NOT touch the live CA dirs.
set -eu
VESSEL=${1:-athena}
ALG=${2:-mldsa44}
PKI=/home/pki/pki-ca/pki
OUT=/tmp/triton_cred/$VESSEL
mkdir -p "$OUT"
PROV="-provider oqsprovider -provider default"

echo "== Issuing PQC leaf for '$VESSEL' using $ALG under the existing RSA CA =="

# 1. vessel PQC keypair (the credential's private key)
openssl genpkey $PROV -algorithm $ALG -out "$OUT/$VESSEL.key" 2>/dev/null
echo "  [1] vessel PQC key: $(wc -c < "$OUT/$VESSEL.key") bytes"

# 2. CSR (vessel asks the CA to certify its PQC pubkey + identity)
openssl req $PROV -new -key "$OUT/$VESSEL.key" -out "$OUT/$VESSEL.csr" \
  -subj "/CN=$VESSEL.vessel.triton/O=space-maritime-research" 2>/dev/null
echo "  [2] CSR: $(wc -c < "$OUT/$VESSEL.csr") bytes"

# 3. CA signs the PQC CSR with its RSA key -> hybrid-chain leaf cert
#    (CA signature alg = sha256WithRSA; leaf SubjectPublicKey = the PQC key)
sudo openssl x509 $PROV -req -in "$OUT/$VESSEL.csr" \
  -CA "$PKI/ca.crt" -CAkey "$PKI/private/ca.key" -CAcreateserial \
  -days 365 -out "$OUT/$VESSEL.crt" 2>/tmp/_issue_err \
  || { echo "  !! signing FAILED:"; cat /tmp/_issue_err; exit 1; }
echo "  [3] leaf cert issued: $(wc -c < "$OUT/$VESSEL.crt") bytes"

# 4. verify the chain: leaf <- existing CA
sudo openssl verify $PROV -CAfile "$PKI/ca.crt" "$OUT/$VESSEL.crt" 2>/tmp/_vfy_err \
  && echo "  [4] CHAIN VERIFY OK (RSA root certifies PQC leaf)" \
  || { echo "  [4] chain verify note:"; cat /tmp/_vfy_err; }

# 5. show what we made (proof it's a PQC leaf under an RSA issuer)
echo "  [5] leaf identity:"
openssl x509 $PROV -in "$OUT/$VESSEL.crt" -noout -subject -issuer 2>/dev/null | sed 's/^/      /'
echo "      Leaf public-key algorithm:"
openssl x509 $PROV -in "$OUT/$VESSEL.crt" -noout -text 2>/dev/null \
  | grep -iE "Public Key Algorithm|Signature Algorithm" | head -2 | sed 's/^/      /'

echo "== DONE. Credential material in $OUT/ =="
echo "   $VESSEL.key (PQC private), $VESSEL.crt (CA-issued PQC leaf), ca.crt = $PKI/ca.crt"
echo "   These feed the cost measurement (s3)."