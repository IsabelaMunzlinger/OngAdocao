package bdTrabalho.OngAplication.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Testes negativos 1–7 e 12 do item 5 do enunciado (ID Token forjado/inválido).
 * Rodar:  ./mvnw test -Dtest=IdTokenValidatorServiceTest
 * A saída do surefire (target/surefire-reports) serve de evidência para o relatório.
 */
class IdTokenValidatorServiceTest {

    static final String ISS = "https://localhost:9000";
    static final String CLIENT_ID = "ong-adocao-client";
    static final String NONCE = "nonce-esperado";
    static final String KID = "key-teste";

    static RSAKey rsa;
    static IdTokenValidatorService validator;

    @BeforeAll
    static void setup() throws Exception {
        rsa = new RSAKeyGenerator(2048).keyID(KID).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();

        RestTemplate rt = mock(RestTemplate.class);
        when(rt.getForObject(eq(ISS + "/.well-known/openid-configuration"), eq(String.class)))
                .thenReturn("{\"issuer\":\"" + ISS + "\",\"jwks_uri\":\"" + ISS + "/jwks.json\"}");
        when(rt.getForObject(eq(ISS + "/jwks.json"), eq(String.class)))
                .thenReturn(new JWKSet(rsa.toPublicJWK()).toString());

        OidcProperties props = new OidcProperties(ISS, ISS + "/authorize", ISS + "/token", ISS + "/userinfo",
                ISS + "/jwks.json", ISS + "/logout", "https://localhost:8443/login?logout=true", CLIENT_ID, "segredo-de-teste",
                "https://localhost:8443/callback", false, 8);
        validator = new IdTokenValidatorService(props, rt);
    }

    // ------------------------------------------------------------ helpers

    static JWTClaimsSet.Builder validClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISS).subject("sub-admin-001").audience(CLIENT_ID)
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(900)))
                .claim("nonce", NONCE).claim("azp", CLIENT_ID)
                .claim("name", "Administrador ONG").claim("email", "admin@ong.local")
                .claim("email_verified", true).claim("role", "admin");
    }

    static String signRs256(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT).keyID(KID).build(), claims);
        jwt.sign(new RSASSASigner(rsa));
        return jwt.serialize();
    }

    static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    static SecurityException rejeita(String token, String trechoDaMensagem) {
        SecurityException ex = assertThrows(SecurityException.class, () -> validator.validateAndParse(token, NONCE));
        System.out.println("   -> REJEITADO: " + ex.getMessage());
        assertTrue(ex.getMessage().contains(trechoDaMensagem),
                "mensagem inesperada: " + ex.getMessage());
        return ex;
    }

    // ------------------------------------------------------------ sanidade

    @Test
    @DisplayName("Token legítimo é aceito (controle positivo)")
    void tokenValidoPassa() throws Exception {
        var claims = validator.validateAndParse(signRs256(validClaims().build()), NONCE);
        assertEquals("sub-admin-001", claims.getSubject());
    }

    // ------------------------------------------------------------ testes negativos

    @Test
    @DisplayName("Negativo #1 — alg \"none\"")
    void t01_algNone() throws Exception {
        String payload = validClaims().build().toString();
        String token = b64("{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"" + KID + "\"}") + "." + b64(payload) + ".";
        rejeita(token, "Algoritmo JWT não permitido");
        // variante com "assinatura" preenchida
        rejeita(b64("{\"alg\":\"none\",\"kid\":\"" + KID + "\"}") + "." + b64(payload) + ".AAAA", "Algoritmo JWT não permitido");
    }

    @Test
    @DisplayName("Negativo #2 — reassinado em HS256 usando a chave pública como segredo")
    void t02_hs256ComChavePublica() throws Exception {
        byte[] segredo = rsa.toRSAPublicKey().getEncoded();          // chave pública usada como HMAC secret
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT).keyID(KID).build(), validClaims().build());
        jwt.sign(new MACSigner(segredo));
        rejeita(jwt.serialize(), "Algoritmo JWT não permitido");
    }

    @Test
    @DisplayName("Negativo #3 — aud de outro client_id")
    void t03_audErrado() throws Exception {
        rejeita(signRs256(validClaims().audience("outro-client").build()), "Audience");
    }

    @Test
    @DisplayName("Negativo #4 — iss diferente do emissor")
    void t04_issErrado() throws Exception {
        rejeita(signRs256(validClaims().issuer("https://evil.example").build()), "Issuer inválido");
    }

    @Test
    @DisplayName("Negativo #5 — exp vencido")
    void t05_expVencido() throws Exception {
        Instant antes = Instant.now().minusSeconds(3600);
        rejeita(signRs256(validClaims().issueTime(Date.from(antes.minusSeconds(900)))
                .expirationTime(Date.from(antes)).build()), "expirado");
    }

    @Test
    @DisplayName("Negativo #6 — iat no futuro")
    void t06_iatFuturo() throws Exception {
        Instant futuro = Instant.now().plusSeconds(3600);
        rejeita(signRs256(validClaims().issueTime(Date.from(futuro))
                .expirationTime(Date.from(futuro.plusSeconds(900))).build()), "iat");
    }

    @Test
    @DisplayName("Negativo #7 — nonce diferente do enviado")
    void t07_nonceDivergente() throws Exception {
        rejeita(signRs256(validClaims().claim("nonce", "outro-nonce").build()), "Nonce");
    }

    @Test
    @DisplayName("Negativo #12 — um caractere alterado na assinatura")
    void t12_assinaturaAdulterada() throws Exception {
        String token = signRs256(validClaims().build());
        String[] p = token.split("\\.");
        char[] sig = p[2].toCharArray();
        sig[10] = (sig[10] == 'A') ? 'B' : 'A';                      // altera no MEIO (o último char tem bits de padding)
        rejeita(p[0] + "." + p[1] + "." + new String(sig), "Assinatura");
    }

    @Test
    @DisplayName("Extra — kid desconhecido => erro (chave não encontrada)")
    void kidDesconhecido() throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("kid-inexistente").build(),
                validClaims().build());
        jwt.sign(new RSASSASigner(rsa));
        rejeita(jwt.serialize(), "Chave pública RSA não encontrada");
    }
}
