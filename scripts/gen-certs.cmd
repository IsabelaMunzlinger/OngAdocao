@echo off
REM Uso: set APP_KEYSTORE_PASSWORD=xxx && set OIDC_TRUSTSTORE_PASSWORD=yyy && scripts\gen-certs.cmd ..\auth-server\certs\auth-server.crt
if "%APP_KEYSTORE_PASSWORD%"=="" (echo Defina APP_KEYSTORE_PASSWORD & exit /b 1)
if "%OIDC_TRUSTSTORE_PASSWORD%"=="" (echo Defina OIDC_TRUSTSTORE_PASSWORD & exit /b 1)
if not exist certs mkdir certs
keytool -genkeypair -alias app -keyalg RSA -keysize 2048 -validity 365 -dname "CN=localhost,O=Trabalho Cyber Security" -ext "SAN=dns:localhost,ip:127.0.0.1" -storetype PKCS12 -keystore certs\app.p12 -storepass %APP_KEYSTORE_PASSWORD%
keytool -importcert -noprompt -alias auth-server -file %1 -storetype PKCS12 -keystore certs\truststore.p12 -storepass %OIDC_TRUSTSTORE_PASSWORD%
