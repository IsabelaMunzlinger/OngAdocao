package bdTrabalho.OngAplication.security;

import bdTrabalho.OngAplication.repository.UsuarioRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;

/**
 * A autenticação é feita EXCLUSIVAMENTE via OIDC (/oauth2/login -> /callback).
 * Não existe formLogin, nem UserDetailsService, nem senha local.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   SecurityContextRepository securityContextRepository,
                                                   UsuarioRepository usuarioRepository,
                                                   OidcProperties oidc) throws Exception {

        var revalidation = new SessionRevalidationFilter(usuarioRepository,
                Duration.ofHours(oidc.absoluteSessionHours() > 0 ? oidc.absoluteSessionHours() : 8));

        http
                .securityContext(sc -> sc.securityContextRepository(securityContextRepository))
                .sessionManagement(sm -> sm.sessionFixation(fix -> fix.changeSessionId()))
                // roda antes da autorização: expiração absoluta + role relida do banco a cada requisição
                .addFilterBefore(revalidation, AuthorizationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // Públicos: início do fluxo OIDC, callback, páginas de erro e estáticos
                        .requestMatchers(
                                "/login", "/oauth2/**", "/callback", "/acesso-negado", "/erro-auth",
                                "/css/**", "/js/**", "/CSS/**", "/JS/**", "/images/**", "/img/**",
                                "/Icones/**", "/webjars/**"
                        ).permitAll()

                        // Área restrita: somente ROLE_ADMIN (autorização no servidor)
                        .requestMatchers("/admin", "/admin/**").hasRole("ADMIN")

                        // Exclusões, edição e cadastro de usuários: somente ADMIN
                        .requestMatchers(HttpMethod.DELETE, "/**").hasRole("ADMIN")
                        .requestMatchers(
                                "/*/excluir", "/*/excluir/**",
                                "/*/deletar", "/*/deletar/**",
                                "/*/remover", "/*/remover/**",
                                "/usuario/editar", "/usuario/editar/**",
                                "/usuario/cadastroUsuario", "/usuario/salvar"
                        ).hasRole("ADMIN")

                        // Telas internas de gestão: ADMIN e OPERADOR (ROLE_USER)
                        .requestMatchers(
                                "/animal/**", "/campanha/**", "/prontuario/**", "/vacina/**",
                                "/doenca/**", "/contato/**", "/endereco/**",
                                "/usuario/listaUsuario",
                                "/adocao/listar", "/adocao/aprovar", "/adocao/reprovar"
                        ).hasAnyRole("ADMIN", "USER")

                        .anyRequest().authenticated()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")                 // POST + CSRF
                        .logoutSuccessHandler((req, res, auth) -> res.sendRedirect(
                                UriComponentsBuilder.fromUriString(oidc.endSessionEndpoint())
                                        .queryParam("post_logout_redirect_uri", oidc.postLogoutRedirectUri())
                                        .build().encode().toUriString()))   // encerra também a sessão no provedor
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("ONG_SESSION_ID")
                        .permitAll()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                        .accessDeniedPage("/acesso-negado")   // mantém HTTP 403
                );

        return http.build();
    }
}
