package bdTrabalho.OngAplication.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
public class GlobalSecurityAdvice {

    @ModelAttribute
    public void addSecurityAttributes(Model model, Authentication authentication) {
        boolean autenticado = authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal());

        boolean isAdmin = autenticado && authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ROLE_ADMIN"));

        boolean isOperador = autenticado && authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ROLE_USER"));

        boolean isAdotante = autenticado && authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ROLE_ADOTANTE"));

        String perfil = "Visitante";
        if (isAdmin) {
            perfil = "Administrador";
        } else if (isOperador) {
            perfil = "Operador";
        } else if (isAdotante) {
            perfil = "Adotante";
        }

        model.addAttribute("autenticado", autenticado);
        model.addAttribute("isAdmin", isAdmin);
        model.addAttribute("isOperador", isOperador);
        model.addAttribute("isAdotante", isAdotante);
        model.addAttribute("usuarioLogado", autenticado ? authentication.getName() : null);
        model.addAttribute("perfilUsuario", perfil);
    }
}