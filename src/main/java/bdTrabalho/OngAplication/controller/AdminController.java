package bdTrabalho.OngAplication.controller;

import bdTrabalho.OngAplication.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/** Rota protegida do item 4.5: só role = admin; qualquer outro perfil recebe HTTP 403. */
@Controller
@RequiredArgsConstructor
public class AdminController {

    private final UsuarioRepository usuarioRepository;

    @PreAuthorize("hasRole('ADMIN')")   // defesa em profundidade (além do SecurityConfig)
    @GetMapping("/admin")
    public String admin(Model model) {
        model.addAttribute("usuarios", usuarioRepository.findAllByOrderByNomeAsc());
        return "admin";
    }
}
