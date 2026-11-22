#!/usr/bin/env bash
# Gera o certificado TLS da aplicação e o truststore que confia no auth-server (somente desenvolvimento).
# Uso: APP_KEYSTORE_PASSWORD=xxx OIDC_TRUSTSTORE_PASSWORD=yyy ./scripts/gen-certs.sh ../auth-server/certs/auth-server.crt
set -euo pipefail
: "${APP_KEYSTORE_PASSWORD:?Defina APP_KEYSTORE_PASSWORD}"
: "${OIDC_TRUSTSTORE_PASSWORD:?Defina OIDC_TRUSTSTORE_PASSWORD}"
AUTH_CRT="${1:?Informe o caminho do auth-server.crt}"
mkdir -p certs
keytool -genkeypair -alias app -keyalg RSA -keysize 2048 -validity 365 \
  -dname "CN=localhost,O=Trabalho Cyber Security" -ext "SAN=dns:localhost,ip:127.0.0.1" \
  -storetype PKCS12 -keystore certs/app.p12 -storepass "$APP_KEYSTORE_PASSWORD"
keytool -importcert -noprompt -alias auth-server -file "$AUTH_CRT" \
  -storetype PKCS12 -keystore certs/truststore.p12 -storepass "$OIDC_TRUSTSTORE_PASSWORD"
echo "OK: certs/app.p12 e certs/truststore.p12"
