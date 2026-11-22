package bdTrabalho.OngAplication.security;

import bdTrabalho.OngAplication.model.Usuarios;
import bdTrabalho.OngAplication.repository.UsuarioRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * A CADA requisição: (1) aplica a expiração absoluta da sessão e
 * (2) relê o usuário no banco e reconstrói a autenticação com a role ATUAL
 * (se a role mudar ou o usuário for removido, o efeito é imediato).
 * Não é um @Bean/@Component de propósito: é registrado só dentro da SecurityFilterChain.
 */
public class SessionRevalidationFilter extends OncePerRequestFilter {

    private final UsuarioRepository usuarios;
    private final Duration absoluteTimeout;

    public SessionRevalidationFilter(UsuarioRepository usuarios, Duration absoluteTimeout) {
        this.usuarios = usuarios;
        this.absoluteTimeout = absoluteTimeout;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute(RoleUtil.SESS_USER_ID) != null) {

            Instant created = (Instant) session.getAttribute(RoleUtil.SESS_CREATED_AT);
            boolean absoluteExpired = created == null || Instant.now().isAfter(created.plus(absoluteTimeout));

            Optional<Usuarios> user = absoluteExpired
                    ? Optional.empty()
                    : usuarios.findById((Integer) session.getAttribute(RoleUtil.SESS_USER_ID));

            if (user.isEmpty()) {
                session.invalidate();
                SecurityContextHolder.clearContext();
                response.sendRedirect(request.getContextPath() + "/login?expired=true");
                return;
            }

            var auth = new UsernamePasswordAuthenticationToken(
                    user.get().getUserName(), null,
                    List.of(new SimpleGrantedAuthority(RoleUtil.toSpringRole(user.get().getRole()))));
            SecurityContext ctx = SecurityContextHolder.createEmptyContext();
            ctx.setAuthentication(auth);
            SecurityContextHolder.setContext(ctx);
        }
        chain.doFilter(request, response);
    }
}
