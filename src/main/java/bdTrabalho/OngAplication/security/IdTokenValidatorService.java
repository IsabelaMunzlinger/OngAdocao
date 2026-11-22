package bdTrabalho.OngAplication.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Valida o ID Token conforme o checklist 4.3 do enunciado (OIDC Core §3.1.3.7, RFC 8725). */
@Slf4j
@Service
@RequiredArgsConstructor
public class IdTokenValidatorService {

    /** Lista FIXA de algoritmos aceitos: o alg do token nunca escolhe o método de verificação. */
    private static final Set<String> ALLOWED_ALGS = Set.of("RS256");
    private static final long CLOCK_SKEW_SECONDS = 120;

    private final OidcProperties props;
    @Qualifier("oidcRestTemplate")
    private final RestTemplate restTemplate;

    private volatile String discoveredJwksUri;

    public JWTClaimsSet validateAndParse(String rawIdToken, String expectedNonce) throws Exception {
        if (rawIdToken == null || rawIdToken.isBlank()) {
            throw new SecurityException("ID Token ausente.");
        }

        String[] parts = rawIdToken.split("\\.", -1);
        if (parts.length != 3) {
            throw new SecurityException("Formato JWS inválido.");
        }

        String decodedHeader;
        String decodedPayload;
        try {
            decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            decodedPayload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new SecurityException("Base64URL inválido no ID Token.");
        }
        // Evidência para o relatório (item 7 do passo a passo). Em produção, não logar claims.
        log.info("=== ID TOKEN DECODIFICADO ===");
        log.info("1. Header   : {}", decodedHeader);
        log.info("2. Payload  : {}", decodedPayload);
        log.info("3. Signature: {}", parts[2]);

        // 1) Checagem do algoritmo ANTES de qualquer outra coisa, lendo o JSON bruto do header
        //    (assim "none" e HS256 são recusados explicitamente, antes do parse da biblioteca).
        Object algRaw;
        try {
            algRaw = JSONObjectUtils.parse(decodedHeader).get("alg");
        } catch (ParseException e) {
            throw new SecurityException("Header JWT malformado.");
        }
        if (!(algRaw instanceof String algName) || "none".equalsIgnoreCase(algName) || !ALLOWED_ALGS.contains(algName)) {
            throw new SecurityException("Algoritmo JWT não permitido: " + algRaw);
        }
        if (parts[2].isEmpty()) {
            throw new SecurityException("ID Token sem assinatura.");
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(rawIdToken);
        } catch (ParseException e) {
            throw new SecurityException("Falha ao parsear JWT: " + e.getMessage(), e);
        }

        JWSHeader header = signedJWT.getHeader();
        JWSAlgorithm alg = header.getAlgorithm();
        if (alg == null || !ALLOWED_ALGS.contains(alg.getName())) {
            throw new SecurityException("Algoritmo JWT não permitido: " + alg);
        }

        // 2) Chave pública do emissor, localizada por kid (jwks_uri vem da descoberta)
        String kid = header.getKeyID();
        if (kid == null || kid.isBlank()) {
            throw new SecurityException("Header JWT sem kid.");
        }

        JWKSet jwkSet = JWKSet.parse(restTemplate.getForObject(resolveJwksUri(), String.class));
        JWK jwk = jwkSet.getKeyByKeyId(kid);
        if (!(jwk instanceof RSAKey rsaKey)) {
            throw new SecurityException("Chave pública RSA não encontrada no JWKS para kid=" + kid);
        }
        if (jwk.getKeyUse() != null && !KeyUse.SIGNATURE.equals(jwk.getKeyUse())) {
            throw new SecurityException("Chave do JWKS não é de assinatura.");
        }
        if (jwk.getAlgorithm() != null && !ALLOWED_ALGS.contains(jwk.getAlgorithm().getName())) {
            throw new SecurityException("Algoritmo da chave do JWKS não permitido.");
        }

        // 3) Assinatura: o verificador é SEMPRE RSA (não depende do alg do token)
        if (!signedJWT.verify(new RSASSAVerifier(rsaKey.toRSAPublicKey()))) {
            throw new SecurityException("Assinatura digital RS256 do ID Token inválida!");
        }

        // 4) Claims — só depois da assinatura conferida
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        if (!props.issuer().equals(claims.getIssuer())) {
            throw new SecurityException("Issuer inválido: esperado " + props.issuer() + ", recebido " + claims.getIssuer());
        }

        List<String> audiences = claims.getAudience();
        if (audiences == null || !audiences.contains(props.clientId())) {
            throw new SecurityException("Audience (aud) não contém o client_id da aplicação.");
        }
        if (audiences.size() > 1 && !props.clientId().equals(claims.getStringClaim("azp"))) {
            throw new SecurityException("Claim azp inválido para múltiplos audiences.");
        }

        Date exp = claims.getExpirationTime();
        if (exp == null || Instant.now().minusSeconds(CLOCK_SKEW_SECONDS).isAfter(exp.toInstant())) {
            throw new SecurityException("ID Token expirado.");
        }

        Date iat = claims.getIssueTime();
        if (iat == null || iat.toInstant().isAfter(Instant.now().plusSeconds(CLOCK_SKEW_SECONDS))) {
            throw new SecurityException("Claim iat inválido ou no futuro.");
        }

        String tokenNonce = claims.getStringClaim("nonce");
        if (expectedNonce == null || !expectedNonce.equals(tokenNonce)) {
            throw new SecurityException("Nonce divergente!");
        }

        if (claims.getSubject() == null || claims.getSubject().isBlank()) {
            throw new SecurityException("Claim sub ausente no ID Token.");
        }
        return claims;
    }

    /** Descoberta (OIDC Discovery): confere que o issuer publicado é o configurado e usa o jwks_uri publicado. */
    private String resolveJwksUri() throws Exception {
        String cached = discoveredJwksUri;
        if (cached != null) {
            return cached;
        }
        String json = restTemplate.getForObject(props.issuer() + "/.well-known/openid-configuration", String.class);
        Map<String, Object> meta = JSONObjectUtils.parse(json);
        if (!props.issuer().equals(meta.get("issuer"))) {
            throw new SecurityException("O issuer publicado na descoberta difere do configurado.");
        }
        if (!(meta.get("jwks_uri") instanceof String uri) || uri.isBlank()) {
            throw new SecurityException("Descoberta sem jwks_uri.");
        }
        discoveredJwksUri = uri;
        return uri;
    }
}
