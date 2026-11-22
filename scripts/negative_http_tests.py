#!/usr/bin/env python3
"""
Testes negativos HTTP do item 5 do enunciado: #8, #9, #10, #11, #13, #14 e #15.
(#1-#7 e #12 estão em src/test/.../IdTokenValidatorServiceTest.java)

Pré-requisitos: auth-server (9000) e aplicação (8443) rodando; `pip install requests`.
Variáveis de ambiente (use os mesmos valores dos .env):
  AUTH_URL (https://localhost:9000)  APP_URL (https://localhost:8443)
  OIDC_CLIENT_ID  OIDC_CLIENT_SECRET  OIDC_REDIRECT_URI
  OPERADOR_PASSWORD (= SEED_USER_PASSWORD)  ADMIN_PASSWORD (= SEED_ADMIN_PASSWORD)
  CA_CERT (opcional: caminho de certs/auth-server.crt; sem ele a verificação TLS é desligada)
"""
import base64, hashlib, html, os, re, secrets, sys
from urllib.parse import urlparse, parse_qs
import requests

AUTH = os.environ.get("AUTH_URL", "https://localhost:9000").rstrip("/")
APP = os.environ.get("APP_URL", "https://localhost:8443").rstrip("/")
CID = os.environ["OIDC_CLIENT_ID"]
SECRET = os.environ["OIDC_CLIENT_SECRET"]
REDIR = os.environ.get("OIDC_REDIRECT_URI", APP + "/callback")
OP_PW = os.environ["OPERADOR_PASSWORD"]
ADM_PW = os.environ["ADMIN_PASSWORD"]
VERIFY = os.environ.get("CA_CERT") or False
if VERIFY is False:
    requests.packages.urllib3.disable_warnings()

results = []

def record(num, desc, expected, ok, detail):
    results.append((num, desc, expected, "PASS" if ok else "FAIL", detail))
    print(f"[{'PASS' if ok else 'FAIL'}] #{num} {desc} -> {detail}")

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def new_pkce():
    v = b64url(secrets.token_bytes(48))
    return v, b64url(hashlib.sha256(v.encode()).digest())

def hidden_fields(page):
    return {k: html.unescape(v) for k, v in
            re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page)}

def authorize_params(state, nonce, challenge, redirect_uri=REDIR):
    return {"response_type": "code", "client_id": CID, "redirect_uri": redirect_uri,
            "scope": "openid profile email", "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256"}

def login_and_get_code(sess, username, password, state, nonce, challenge):
    """Faz o papel do navegador: GET /authorize, preenche o form (com _csrf) e devolve o `code`."""
    r = sess.get(f"{AUTH}/authorize", params=authorize_params(state, nonce, challenge), verify=VERIFY)
    assert r.status_code == 200, f"GET /authorize => {r.status_code}"
    form = hidden_fields(r.text)
    form.update({"username": username, "password": password, "consent": "true"})
    r = sess.post(f"{AUTH}/authorize", data=form, allow_redirects=False, verify=VERIFY)
    loc = r.headers.get("Location", "")
    q = parse_qs(urlparse(loc).query)
    return q.get("code", [None])[0], q.get("state", [None])[0], r

def exchange(sess, code, verifier, redirect_uri=REDIR):
    return sess.post(f"{AUTH}/token", verify=VERIFY, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "code_verifier": verifier, "client_id": CID, "client_secret": SECRET})

def fresh_code(sess, username="operador", password=OP_PW):
    verifier, challenge = new_pkce()
    state = b64url(secrets.token_bytes(16))
    code, st, _ = login_and_get_code(sess, username, password, state, b64url(secrets.token_bytes(16)), challenge)
    assert code and st == state, "não obteve code (credenciais corretas? rate limit?)"
    return code, verifier

# ---------------------------------------------------------------- #8 state
def t08():
    for label, qs in (("state divergente", "code=abc&state=forjado"), ("state ausente", "code=abc")):
        s = requests.Session()
        s.get(f"{APP}/oauth2/login", allow_redirects=False, verify=VERIFY)   # cria state na sessão
        r = s.get(f"{APP}/callback?{qs}", allow_redirects=False, verify=VERIFY)
        ok = r.status_code == 200 and "state" in r.text.lower() and "abortado" in r.text.lower()
        record(8, f"Callback com {label}", "Fluxo abortado antes da troca do code", ok, f"HTTP {r.status_code}, fluxo abortado={ok}")

# ---------------------------------------------------------------- #9 reuso do code
def t09():
    s = requests.Session()
    code, verifier = fresh_code(s)
    r1 = exchange(s, code, verifier)
    at = r1.json().get("access_token") if r1.status_code == 200 else None
    r2 = exchange(s, code, verifier)
    ui = requests.get(f"{AUTH}/userinfo", headers={"Authorization": f"Bearer {at}"}, verify=VERIFY)
    ok = r1.status_code == 200 and r2.status_code == 400 and r2.json().get("error") == "invalid_grant" and ui.status_code == 401
    record(9, "Reutilização do authorization code", "invalid_grant + revogação dos tokens", ok,
           f"1ª troca={r1.status_code}; 2ª={r2.status_code} {r2.json()}; /userinfo c/ token revogado={ui.status_code}")

# ---------------------------------------------------------------- #10 verifier errado
def t10():
    s = requests.Session()
    code, _ = fresh_code(s)
    r = exchange(s, code, b64url(secrets.token_bytes(48)))
    ok = r.status_code == 400 and r.json().get("error") == "invalid_grant"
    record(10, "code_verifier incorreto no /token", "invalid_grant", ok, f"HTTP {r.status_code} {r.json()}")

# ---------------------------------------------------------------- #11 redirect_uri exata
def t11():
    variantes = {"barra final extra": REDIR + "/", "parâmetro adicional": REDIR + "?x=1", "subcaminho": REDIR + "/sub"}
    s = requests.Session()
    _, challenge = new_pkce()
    for nome, uri in variantes.items():
        r = s.get(f"{AUTH}/authorize", params=authorize_params("s", "n", challenge, uri), allow_redirects=False, verify=VERIFY)
        ok = r.status_code == 400 and "Location" not in r.headers
        record(11, f"/authorize com redirect_uri + {nome}", "Rejeitado, sem redirect", ok, f"HTTP {r.status_code}, Location={r.headers.get('Location')}")
    code, verifier = fresh_code(s)
    r = exchange(s, code, verifier, REDIR + "/")
    ok = r.status_code == 400 and r.json().get("error") == "invalid_grant"
    record(11, "/token com redirect_uri diferente do /authorize", "invalid_grant", ok, f"HTTP {r.status_code} {r.json()}")

# ---------------------------------------------------------------- #13 /admin com role=user
def app_login(username, password):
    s = requests.Session()
    r = s.get(f"{APP}/oauth2/login", allow_redirects=False, verify=VERIFY)
    auth_url = r.headers["Location"]
    r = s.get(auth_url, verify=VERIFY)
    form = hidden_fields(r.text); form.update({"username": username, "password": password, "consent": "true"})
    r = s.post(f"{AUTH}/authorize", data=form, allow_redirects=False, verify=VERIFY)
    cb = r.headers["Location"]
    r = s.get(cb, allow_redirects=False, verify=VERIFY)
    return s, r

def t13():
    s, r = app_login("operador", OP_PW)
    a = s.get(f"{APP}/admin", allow_redirects=False, verify=VERIFY)
    record(13, "Acesso a /admin com role = user", "HTTP 403", a.status_code == 403, f"login HTTP {r.status_code}; /admin HTTP {a.status_code}")
    s2, r2 = app_login("admin", ADM_PW)
    a2 = s2.get(f"{APP}/admin", allow_redirects=False, verify=VERIFY)
    record(13, "(controle) Acesso a /admin com role = admin", "HTTP 200", a2.status_code == 200, f"/admin HTTP {a2.status_code}")

# ---------------------------------------------------------------- #14 userinfo
def t14():
    r = requests.get(f"{AUTH}/userinfo", verify=VERIFY)
    ok = r.status_code == 401 and "bearer" in r.headers.get("WWW-Authenticate", "").lower()
    record(14, "/userinfo sem token", "401 + WWW-Authenticate", ok, f"HTTP {r.status_code}, WWW-Authenticate={r.headers.get('WWW-Authenticate')}")
    r = requests.get(f"{AUTH}/userinfo", headers={"Authorization": "Bearer token-invalido-ou-expirado"}, verify=VERIFY)
    ok = r.status_code == 401 and "bearer" in r.headers.get("WWW-Authenticate", "").lower()
    record(14, "/userinfo com token inválido/expirado", "401 + WWW-Authenticate", ok, f"HTTP {r.status_code}, WWW-Authenticate={r.headers.get('WWW-Authenticate')}")

# ---------------------------------------------------------------- #15 força bruta
def t15():
    s = requests.Session()
    alvo = "alvo-" + secrets.token_hex(3)        # usuário próprio p/ não bloquear o 'operador' real
    _, challenge = new_pkce()
    codigos = []
    for i in range(1, 9):
        r = s.get(f"{AUTH}/authorize", params=authorize_params("s", "n", challenge), verify=VERIFY)
        form = hidden_fields(r.text); form.update({"username": alvo, "password": f"errada{i}", "consent": "true"})
        p = s.post(f"{AUTH}/authorize", data=form, allow_redirects=False, verify=VERIFY)
        codigos.append(p.status_code)
    ok = codigos[:5] == [401] * 5 and 429 in codigos[5:]
    record(15, "Tentativas repetidas de login (força bruta)", "Bloqueio por rate limiting (429)", ok, f"status por tentativa: {codigos}")

if __name__ == "__main__":
    for t in (t08, t09, t10, t11, t13, t14, t15):
        try:
            t()
        except Exception as e:                      # noqa: BLE001
            record(int(t.__name__[1:]), t.__name__, "-", False, f"erro: {e!r}")
    print("\n| # | Cenário | Esperado | Resultado |\n|---|---|---|---|")
    for n, d, e, st, det in results:
        print(f"| {n} | {d} | {e} | {st} |")
    sys.exit(0 if all(r[3] == "PASS" for r in results) else 1)
