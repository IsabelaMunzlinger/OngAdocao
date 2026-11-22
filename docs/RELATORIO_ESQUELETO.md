# Relatório A1/3 — Cyber Security — OAuth 2.0 + OpenID Connect (máx. 6 páginas)
Grupo: ______  ·  Opção 1 (Servidor de Autorização próprio)  ·  Entrega: 26/11/2026

## 1. Diagrama do fluxo
```mermaid
sequenceDiagram
  participant U as Usuário (navegador)
  participant A as Aplicação (RP) :8443
  participant S as Auth Server (OP) :9000
  U->>A: clica "Entrar" (/oauth2/login)
  A->>A: gera state, nonce, code_verifier; challenge = B64URL(SHA256(verifier))
  A-->>U: 302 /authorize?response_type=code&client_id&redirect_uri&scope&state&nonce&code_challenge&method=S256
  U->>S: GET /authorize (valida client_id + redirect_uri exata)
  S-->>U: formulário de login + consentimento
  U->>S: POST /authorize (usuário + senha) — senha só aqui
  S-->>U: 302 redirect_uri?code=...&state=...
  U->>A: GET /callback?code&state
  A->>A: confere state (aborta se divergir)
  A->>S: POST /token (code, redirect_uri, code_verifier, client_id/secret)
  S-->>A: access_token (opaco) + id_token (JWT RS256)
  A->>S: GET /.well-known/openid-configuration e /jwks.json
  A->>A: valida ID Token (checklist 4.3)
  A->>S: GET /userinfo (Bearer) — confere sub
  A->>A: vínculo iss+sub, role do claim, sessão local (id rotacionado)
```

## 2. ID Token decodificado
Cole aqui as 3 linhas do log da aplicação (`1. Header`, `2. Payload`, `3. Signature`) de um login real.

## 3. Checklist 4.3 (evidência = onde está no código / teste)
| # | Verificação | Onde | Evidência |
|---|---|---|---|
| 1 | Assinatura por `kid`; chave ausente = erro | `IdTokenValidatorService` (JWKS + `RSASSAVerifier`) | teste #12 e `kidDesconhecido` |
| 2 | Algoritmo na lista fixa; `none` rejeitado | `ALLOWED_ALGS` + checagem do header bruto | testes #1, #2 |
| 3 | `iss` = issuer da descoberta | `resolveJwksUri()` + comparação de `iss` | teste #4 |
| 4 | `aud` contém o `client_id` | idem | teste #3 |
| 5 | `azp` se `aud` múltiplo | idem | — (código) |
| 6 | `exp` no futuro (skew 120 s) | idem | teste #5 |
| 7 | `iat` não no futuro | idem | teste #6 |
| 8 | `nonce` idêntico | idem | teste #7 |
| 9 | `sub` → id interno (por iss + sub) | `OidcAuthController` | log do login |
| 10 | `sub` do `/userinfo` = do ID Token | `OidcAuthController` | log do login |

## 4. Testes negativos (item 5) — cole prints/saída
| # | Cenário | Esperado | Como rodar | Evidência |
|---|---|---|---|---|
| 1–7, 12 | ID Token forjado | Rejeitado | `./mvnw test -Dtest=IdTokenValidatorServiceTest` | surefire |
| 8 | state divergente/ausente | Fluxo abortado | `scripts/negative_http_tests.py` | tabela PASS/FAIL |
| 9 | reuso do code | invalid_grant + revogação | idem | idem |
| 10 | code_verifier errado | invalid_grant | idem | idem |
| 11 | redirect_uri alterada | Rejeitado | idem | idem |
| 13 | /admin com role=user | 403 | idem | idem |
| 14 | /userinfo sem token/expirado | 401 + WWW-Authenticate | idem | idem |
| 15 | força bruta | rate limiting (429) | idem | idem |

## 5. Justificativas
- **RS256**: assinatura assimétrica; a aplicação só tem a chave pública (JWKS). HS256 exigiria segredo compartilhado — proibido no enunciado e base do ataque #2.
- **TTL 900 s**: limita a janela de uso de um token vazado; o ID Token só serve para estabelecer a sessão local (que tem inatividade de 30 min e limite absoluto de 8 h).
- **Code 60 s + uso único + PKCE S256**: mitiga interceptação do code.
- **Role do claim** (validado, lista fixa) + releitura do banco a cada requisição.
- **Cadastro no provedor**: a senha existe só no auth-server (bcrypt 12); a aplicação nunca a vê.
