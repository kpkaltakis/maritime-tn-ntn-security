#!/bin/bash
# s1_preflight.sh -- run ON VM-11 (pki-ca). READ-ONLY health check.
# Confirms the CA + oqsprovider actually work BEFORE we issue or measure anything.
# Your discipline: health-check before measure. Nothing here writes/issues.
set -u
PKI=/home/pki/pki-ca/pki
echo "==================== PRE-FLIGHT (VM-11 pki-ca) ===================="

echo "--- [1] oqsprovider actually loads + can list PQC sig algs? ---"
openssl list -signature-algorithms -provider oqsprovider -provider default 2>/dev/null \
  | grep -iE "mldsa|dilithium|falcon" | head -10 || echo "  !! oqsprovider sig algs NOT listing — STOP, fix provider first"

echo "--- [2] can oqsprovider generate a PQC key? (to /tmp, throwaway) ---"
openssl genpkey -provider oqsprovider -provider default -algorithm mldsa44 -out /tmp/_pf_test.key 2>/tmp/_pf_err \
  && echo "  OK: mldsa44 keygen works ($(wc -c </tmp/_pf_test.key) bytes)" \
  || { echo "  !! mldsa44 keygen FAILED:"; cat /tmp/_pf_err; }
# also try falcon512 (name may be falcon512 or falconpadded512 depending on build)
for alg in falcon512 falconpadded512; do
  openssl genpkey -provider oqsprovider -provider default -algorithm $alg -out /tmp/_pf_f.key 2>/dev/null \
    && { echo "  OK: $alg keygen works"; FALCON_NAME=$alg; break; }
done

echo "--- [3] existing CA files present + readable? ---"
for f in ca.crt private/ca.key openssl-easyrsa.cnf index.txt serial; do
  if sudo test -e "$PKI/$f"; then echo "  present: $f"; else echo "  MISSING: $f"; fi
done

echo "--- [4] what is the CA key + how does easyrsa sign? (helps pick issue method) ---"
sudo openssl x509 -in "$PKI/ca.crt" -noout -subject -issuer 2>/dev/null
echo "  CA cnf signing section (how leaves get signed):"
sudo grep -iE "default_md|policy|x509_extensions|copy_extensions|default_days" "$PKI/openssl-easyrsa.cnf" 2>/dev/null | head

echo "--- [5] can the RSA CA sign a PQC CSR? (THE key question for Option 1) ---"
echo "  (RSA CA signs the leaf; leaf carries a PQC public key. The CA's OWN signature"
echo "   stays sha256WithRSA — that's the hybrid-chain migration story, expected + fine.)"
echo "  Verifying openssl can do 'ca-sign-a-PQC-CSR' is step 6 of issuance, dry-run there."

echo "--- cleanup throwaway keys ---"
rm -f /tmp/_pf_test.key /tmp/_pf_f.key /tmp/_pf_err
echo "==================== PRE-FLIGHT DONE ===================="
echo "If [1] and [2] show PQC algs working and [3] shows CA files present, we issue."
echo "Tell me the FALCON algorithm name that worked (falcon512 vs falconpadded512)."