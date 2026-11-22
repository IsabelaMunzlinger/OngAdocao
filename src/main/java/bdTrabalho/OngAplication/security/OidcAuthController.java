package bdTrabalho.OngAplication.security;

import bdTrabalho.OngAplication.model.Usuarios;
import bdTrabalho.OngAplication.repository.UsuarioRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

@Slf4j
@Controller
@RequiredArgsConstructor
public class OidcAuthController {

    private static final String SESS_STATE = "OIDC_STATE";
    private static final String SESS_NONCE = "OIDC_NONCE";
    private static final String SESS_VERIFIER = "OIDC_CODE_VERIFIER";

    private static final String MSG_GENERICA = "Não foi possível concluir o login. Tente novamente.";

    private final OidcProperties props;
    @Qualifier("oidcRestTemplate")
    private final RestTemplate restTemplate;
    private final IdTokenValidatorService idTokenValidator;
    private final UsuarioRepository usuarioRepository;
    private final SecurityContextRepository securityContextRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/erro-auth")
    public String erroAuthPage() {
        return "erro-auth";
    }

    // todos os métodos: o AccessDeniedHandler faz forward preservando o método original (ex.: POST)
    @RequestMapping("/acesso-negado")
    public String acessoNegadoPage() {
        return "acesso-negado";
    }

    // ---------------------------------------------------------------- passo 1-2: início do fluxo

    @GetMapping("/oauth2/login")
    public String startOidcLogin(HttpSession session) throws Exception {
        String state = generateRandomUrlSafe(32);   // 256 bits
        String nonce = generateRandomUrlSafe(32);
        String codeVerifier = generateRandomUrlSafe(48);
        String codeChallenge = computeS256Challenge(codeVerifier);

        session.setAttribute(SESS_STATE, state);
        session.setAttribute(SESS_NONCE, nonce);
        session.setAttribute(SESS_VERIFIER, codeVerifier);

        String authorizeUrl = UriComponentsBuilder.fromUriString(props.authorizationEndpoint())
                .queryParam("response_type", "code")
                .queryParam("client_id", props.clientId())
                .queryParam("redirect_uri", props.redirectUri())
                .queryParam("scope", "openid profile email")
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256")
                .build()
                .encode()
                .toUriString();

        return "redirect:" + authorizeUrl;
    }

    // ---------------------------------------------------------------- passo 4-12: callback

    @GetMapping("/callback")
    public String handleCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(name = "error_description", required = false) String errorDescription,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        HttpSession session = request.getSession(false);

        // 4.6: erro do provedor -> mensagem amigável, log, nenhuma sessão
        if (error != null) {
            log.warn("Erro retornado pelo Provedor OIDC: error={}, description={}", error, errorDescription);
            if (session != null) {
                limparEstadoOidc(session);
            }
            return erro(model, "A autenticação foi cancelada ou negada pelo provedor de identidade.");
        }

        if (session == null) {
            return erro(model, "Sessão expirada ou inválida durante o login.");
        }

        String expectedState = (String) session.getAttribute(SESS_STATE);
        String expectedNonce = (String) session.getAttribute(SESS_NONCE);
        String codeVerifier = (String) session.getAttribute(SESS_VERIFIER);
        limparEstadoOidc(session); // uso único: um callback consome o state/nonce/verifier

        // passo 5: state divergente/ausente => aborta ANTES de qualquer troca do code
        if (state == null || expectedState == null || !constantTimeEquals(expectedState, state)) {
            log.error("Falha de validação CSRF: state divergente ou ausente. Fluxo abortado.");
            return erro(model, "Falha de segurança (state inválido). Fluxo abortado.");
        }

        if (code == null || code.isBlank() || codeVerifier == null || expectedNonce == null) {
            return erro(model, "Código de autorização ausente.");
        }

        try {
            // passo 6: troca do code (UMA única tentativa, com timeout no RestTemplate)
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "authorization_code");
            form.add("code", code);
            form.add("redirect_uri", props.redirectUri());
            form.add("code_verifier", codeVerifier);
            form.add("client_id", props.clientId());
            form.add("client_secret", props.clientSecret());

            JsonNode tokenBody = restTemplate.postForObject(
                    props.tokenEndpoint(), new HttpEntity<>(form, headers), JsonNode.class);

            if (tokenBody == null || !tokenBody.hasNonNull("id_token")) {
                throw new SecurityException("Resposta do /token não contém id_token.");
            }

            String idToken = tokenBody.get("id_token").asText();
            String accessToken = tokenBody.hasNonNull("access_token") ? tokenBody.get("access_token").asText() : null;

            // passos 7-9: decompõe (log), valida o ID Token e só então confia no sub
            JWTClaimsSet claims = idTokenValidator.validateAndParse(idToken, expectedNonce);
            String sub = claims.getSubject();

            // checklist 10: sub do /userinfo == sub do ID Token (sub é OBRIGATÓRIO na resposta)
            if (accessToken != null && props.userinfoEndpoint() != null) {
                HttpHeaders uiHeaders = new HttpHeaders();
                uiHeaders.setBearerAuth(accessToken);
                ResponseEntity<JsonNode> uiResp = restTemplate.exchange(
                        props.userinfoEndpoint(), HttpMethod.GET, new HttpEntity<>(uiHeaders), JsonNode.class);
                JsonNode uiBody = uiResp.getBody();
                if (uiBody == null || !uiBody.hasNonNull("sub") || !sub.equals(uiBody.get("sub").asText())) {
                    throw new SecurityException("Divergência entre sub do ID Token e /userinfo.");
                }
            }
            // access token e id_token ficam só nesta variável local: descartados ao sair do método

            // passo 10: vínculo por sub (iss já validado == emissor configurado)
            // passo 12: a role vem do claim `role` do token já validado (lista fixa; padrão = menor privilégio)
            String role = RoleUtil.fromVerifiedClaim(claims.getStringClaim("role"));

            Optional<Usuarios> usuarioOpt = usuarioRepository.findByOidcSub(sub);
            if (usuarioOpt.isEmpty()) {
                if (!props.autoProvision()) {
                    log.warn("Login recusado: sub sem vínculo na tabela Usuarios.");
                    return erro(model, "Seu usuário não está autorizado nesta aplicação.");
                }
                usuarioOpt = Optional.of(provisionar(claims, role));
            }
            Usuarios usuario = usuarioOpt.get();

            // vínculo por iss + sub e role sincronizada com o claim verificado
            String iss = claims.getIssuer();
            boolean alterado = false;
            if (usuario.getOidcIssuer() == null) {
                usuario.setOidcIssuer(iss);
                alterado = true;
            } else if (!usuario.getOidcIssuer().equals(iss)) {
                throw new SecurityException("O sub pertence a outro emissor (iss diverge do vínculo).");
            }
            if (!role.equals(usuario.getRole())) {
                log.info("Role sincronizada com o claim do token: {} -> {}", usuario.getRole(), role);
                usuario.setRole(role);
                alterado = true;
            }

           String pref = claims.getStringClaim("preferred_username");
            if (pref != null && !pref.isBlank() && usuario.getUserName() != null
                    && usuario.getUserName().startsWith("oidc-")
                    && !usuarioRepository.existsByUserName(pref)) {
                usuario.setUserName(pref);
                alterado = true;
            }

            if (alterado) {
                usuario = usuarioRepository.save(usuario);
            }

            // passo 11: nova sessão local; o id da sessão é ROTACIONADO no login
            request.changeSessionId();
            HttpSession newSession = request.getSession(true);
            newSession.setAttribute(RoleUtil.SESS_USER_ID, usuario.getId());   // só o id interno
            newSession.setAttribute(RoleUtil.SESS_CREATED_AT, Instant.now());   // p/ expiração absoluta

            String springRole = RoleUtil.toSpringRole(usuario.getRole());
            var auth = new UsernamePasswordAuthenticationToken(
                    usuario.getUserName(), null, List.of(new SimpleGrantedAuthority(springRole)));
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(auth);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);

            return "ROLE_ADOTANTE".equals(springRole) ? "redirect:/adocao" : "redirect:/menuPrincipal";

        } catch (SecurityException e) {
            log.warn("ID Token/fluxo OIDC rejeitado: {}", e.getMessage());   // detalhe só no log
            return erro(model, MSG_GENERICA);
        } catch (Exception e) {
            log.error("Erro na troca/validação OIDC: {}", e.toString());
            return erro(model, MSG_GENERICA);
        }
    }

    /** Cria usuário SOMENTE com dados do token já validado (role = claim verificado, lista fixa). */
    private Usuarios provisionar(JWTClaimsSet claims, String role) throws Exception {
        String sub = claims.getSubject();
        String nome = claims.getStringClaim("name");
        if (nome == null || nome.isBlank()) {
            nome = "Usuário OIDC";
        }
        String email = claims.getStringClaim("email");
        boolean emailVerificado = Boolean.TRUE.equals(claims.getBooleanClaim("email_verified"));

        String preferido = claims.getStringClaim("preferred_username");
        String userName;
        if (preferido != null && !preferido.isBlank() && !usuarioRepository.existsByUserName(preferido)) {
            userName = preferido;
        } else if (email != null && emailVerificado && !usuarioRepository.existsByUserName(email)) {
            userName = email;
        } else {
            userName = "oidc-" + HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(sub.getBytes(StandardCharsets.UTF_8))).substring(0, 32);
        }

        Usuarios u = new Usuarios();
        u.setUserName(userName);   // apenas exibição
        u.setFullName(nome);
        u.setNome(nome);
        u.setOidcSub(sub);         // chave de vínculo
        u.setOidcIssuer(claims.getIssuer());
        u.setRole(role);
        u.setCreatedAt(LocalDateTime.now());
        u.setDataCadastro(LocalDateTime.now());
        log.info("Usuário provisionado a partir do ID Token (sub={})", sub);
        return usuarioRepository.save(u);
    }

    private String erro(Model model, String mensagem) {
        model.addAttribute("mensagemErro", mensagem);
        return "erro-auth";
    }

    private void limparEstadoOidc(HttpSession session) {
        session.removeAttribute(SESS_STATE);
        session.removeAttribute(SESS_NONCE);
        session.removeAttribute(SESS_VERIFIER);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private String generateRandomUrlSafe(int byteLength) {
        byte[] bytes = new byte[byteLength];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String computeS256Challenge(String verifier) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}