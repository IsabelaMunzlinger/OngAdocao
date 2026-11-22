package bdTrabalho.OngAplication.controller;

import bdTrabalho.OngAplication.dto.UsuarioDTO;
import bdTrabalho.OngAplication.model.ENUM.Genero;
import bdTrabalho.OngAplication.model.Usuarios;
import bdTrabalho.OngAplication.service.UsuarioService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Set;

@Controller
@RequestMapping("/usuario")
@RequiredArgsConstructor
public class UsuarioController {

    private final UsuarioService usuarioService;

    private static final Set<String> ROLES_VALIDAS = Set.of("admin", "user", "adotante");

    private boolean isUsuarioAutenticado(Authentication auth) {
        return auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal());
    }

    private boolean isUsuarioAdmin(Authentication auth) {
        return isUsuarioAutenticado(auth) && auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(r -> r.equals("ROLE_ADMIN"));
    }

    @GetMapping("/cadastroUsuario")
    public String mostrarFormularioDeCadastro(Model model) {
        model.addAttribute("usuarioDTO", new UsuarioDTO(null, null, null, null, null, null, null, null, "adotante"));
        model.addAttribute("generos", Genero.values());
        return "cadastros/usuarioCadastro";
    }

    @PostMapping("/salvar")
    public String salvarUsuario(@Valid @ModelAttribute("usuarioDTO") UsuarioDTO usuarioDTO,
                                BindingResult result,
                                Authentication authentication,
                                Model model,
                                RedirectAttributes redirectAttributes) {

        boolean autenticado = isUsuarioAutenticado(authentication);
        boolean isAdmin = isUsuarioAdmin(authentication);
        boolean isEdicao = usuarioDTO.id() != null && usuarioDTO.id() > 0;

        // Apenas ADMIN pode editar usuários existentes
        if (isEdicao && !isAdmin) {
            throw new AccessDeniedException("Apenas administradores podem editar usuários.");
        }

        // Rota restrita a ADMIN no SecurityConfig; a role ainda é validada contra uma lista fixa.
        String roleFinal = (isAdmin && usuarioDTO.role() != null && ROLES_VALIDAS.contains(usuarioDTO.role().trim().toLowerCase()))
                ? usuarioDTO.role().trim().toLowerCase()
                : "adotante";

        UsuarioDTO dtoSanitizado = new UsuarioDTO(
                usuarioDTO.id(),
                usuarioDTO.nome(),
                usuarioDTO.userName(),
                usuarioDTO.cpf(),
                usuarioDTO.dataNascimento(),
                usuarioDTO.genero(),
                usuarioDTO.foto(),
                usuarioDTO.oidcSub(),
                roleFinal
        );

        if (result.hasErrors()) {
            model.addAttribute("generos", Genero.values());
            return "cadastros/usuarioCadastro";
        }

        try {
            usuarioService.salvar(dtoSanitizado);

            if (!autenticado) {
                return "redirect:/login";
            }

            String mensagem = !isEdicao
                    ? "Usuário cadastrado com sucesso!"
                    : "Usuário atualizado com sucesso!";
            redirectAttributes.addFlashAttribute("sucesso", mensagem);

        } catch (IllegalArgumentException e) {
            model.addAttribute("erro", e.getMessage());
            model.addAttribute("generos", Genero.values());
            return "cadastros/usuarioCadastro";
        }

        return "redirect:/usuario/listaUsuario";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/editar")
    public String mostrarFormularioDeEdicao(@RequestParam("id") Integer id, Model model) {
        Usuarios usuarioExistente = usuarioService.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("ID de usuário inválido: " + id));

        UsuarioDTO usuarioDTO = UsuarioDTO.fromEntity(usuarioExistente);
        model.addAttribute("usuarioDTO", usuarioDTO);
        model.addAttribute("generos", Genero.values());
        return "cadastros/usuarioCadastro";
    }

    @GetMapping("/listaUsuario")
    public String listaUsuario(Model model) {
        List<Usuarios> todosOsUsuarios = usuarioService.findAll();
        model.addAttribute("listaUsuarios", todosOsUsuarios);
        return "listagens/listarUsuarios";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/excluir")
    public String excluirUsuario(@RequestParam("id") Integer id, RedirectAttributes redirectAttributes) {
        try {
            usuarioService.excluirPorId(id);
            redirectAttributes.addFlashAttribute("sucesso", "Usuário excluído com sucesso!");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("erro", "Erro ao excluir usuário: " + e.getMessage());
        }
        return "redirect:/usuario/listaUsuario";
    }
}