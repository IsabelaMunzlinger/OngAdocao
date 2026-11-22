package bdTrabalho.OngAplication.controller;

import bdTrabalho.OngAplication.dto.AdocaoDTO;
import bdTrabalho.OngAplication.model.Adocoes;
import bdTrabalho.OngAplication.model.Animais;
import bdTrabalho.OngAplication.model.ENUM.PorteAnimal;
import bdTrabalho.OngAplication.model.ENUM.TipoAnimal;
import bdTrabalho.OngAplication.model.Usuarios;
import bdTrabalho.OngAplication.repository.UsuarioRepository;
import bdTrabalho.OngAplication.service.AdocaoService;
import bdTrabalho.OngAplication.service.AnimalService;
import bdTrabalho.OngAplication.service.UsuarioService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDateTime;
import java.util.List;

@Controller
@RequestMapping("/adocao")
@RequiredArgsConstructor
public class AdocaoController {

    private final AdocaoService adocaoService;
    private final AnimalService animalService;
    private final UsuarioService usuarioService;
    private final UsuarioRepository usuarioRepository;

    private boolean isAdotante(Authentication auth) {
        return auth != null && auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(r -> r.equals("ROLE_ADOTANTE"));
    }

    @GetMapping
    public String mostrarVitrine(
            Model model,
            @RequestParam(required = false) TipoAnimal tipo,
            @RequestParam(required = false) String cor
    ) {
        model.addAttribute("tiposDeAnimal", TipoAnimal.values());
        model.addAttribute("portesDeAnimal", PorteAnimal.values());
        model.addAttribute("filtroTipo", tipo);
        model.addAttribute("filtroCor", cor);
        model.addAttribute("animaisFiltrados", animalService.findAnimaisDisponiveisComFiltros(tipo, cor));

        return "listagens/adocao";
    }

    @GetMapping("/cadastrar")
    public String mostrarFormularioAdocao(
            @RequestParam(required = false) Integer animalId,
            Model model,
            Authentication authentication) {

        List<Animais> animaisDisponiveis = animalService.findAllFilteredBySituacao("D");
        model.addAttribute("animaisDisponiveis", animaisDisponiveis);

        Animais animalSelecionado = (animalId != null)
                ? animaisDisponiveis.stream()
                .filter(a -> a.getId() == animalId)
                .findFirst()
                .orElse(null)
                : null;
        model.addAttribute("animalSelecionado", animalSelecionado);

        Integer idInicial = animalSelecionado != null ? animalSelecionado.getId() : null;

        if (isAdotante(authentication)) {
            Usuarios adotanteLogado = usuarioRepository.findByUserName(authentication.getName())
                    .or(() -> usuarioRepository.findByCpf(authentication.getName()))
                    .orElse(null);

            Integer adotanteId = adotanteLogado != null ? adotanteLogado.getId() : null;
            model.addAttribute("adocaoDTO", new AdocaoDTO(null, LocalDateTime.now(), "", idInicial, adotanteId));
            model.addAttribute("adotanteFixo", adotanteLogado);
            model.addAttribute("todosUsuarios", List.of());
        } else {
            model.addAttribute("adocaoDTO", new AdocaoDTO(null, LocalDateTime.now(), "", idInicial, null));
            model.addAttribute("adotanteFixo", null);
            model.addAttribute("todosUsuarios", usuarioService.findAll());
        }

        return "cadastros/adocaoCadastro";
    }

    @PostMapping("/salvar")
    public String salvarAdocao(@Valid @ModelAttribute("adocaoDTO") AdocaoDTO adocaoDTO,
                               BindingResult result,
                               Authentication authentication,
                               RedirectAttributes redirectAttributes,
                               Model model) {

        boolean adotante = isAdotante(authentication);
        AdocaoDTO dtoFinal = adocaoDTO;

        if (adotante) {
            Usuarios adotanteLogado = usuarioRepository.findByUserName(authentication.getName())
                    .or(() -> usuarioRepository.findByCpf(authentication.getName()))
                    .orElseThrow(() -> new IllegalArgumentException("Cadastro do adotante não encontrado."));

            dtoFinal = new AdocaoDTO(
                    adocaoDTO.id(),
                    adocaoDTO.dataAdocao() != null ? adocaoDTO.dataAdocao() : LocalDateTime.now(),
                    adocaoDTO.observacoes(),
                    adocaoDTO.animalId(),
                    adotanteLogado.getId()
            );
        }

        if (result.hasErrors()) {
            model.addAttribute("animaisDisponiveis", animalService.findAllFilteredBySituacao("D"));
            model.addAttribute("todosUsuarios", adotante ? List.of() : usuarioService.findAll());
            return "cadastros/adocaoCadastro";
        }

        try {
            adocaoService.solicitarAdocao(dtoFinal);
            redirectAttributes.addFlashAttribute("sucesso", "Solicitação de adoção registrada com sucesso! Aguardando análise.");
            return adotante ? "redirect:/adocao/minhas-solicitacoes" : "redirect:/adocao/listar";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("erro", "Erro ao registrar adoção: " + e.getMessage());
            return adotante ? "redirect:/adocao/minhas-solicitacoes" : "redirect:/adocao/listar";
        }
    }

    @GetMapping("/listar")
    public String listarAdocoes(Model model) {
        List<Adocoes> todasAsAdocoes = adocaoService.findAll();
        model.addAttribute("listaAdocoes", todasAsAdocoes);
        return "listagens/listarAdocoes";
    }

    @PostMapping("/aprovar")
    public String aprovarAdocao(@RequestParam("adocaoId") int adocaoId, RedirectAttributes redirectAttributes) {
        try {
            adocaoService.aprovarAdocao(adocaoId);
            redirectAttributes.addFlashAttribute("sucesso", "Adoção aprovada com sucesso!");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("erro", "Erro ao aprovar adoção: " + e.getMessage());
        }
        return "redirect:/adocao/listar";
    }

    @PostMapping("/reprovar")
    public String reprovarAdocao(@RequestParam("adocaoId") int adocaoId,
                                 @RequestParam("motivo") String motivo,
                                 RedirectAttributes redirectAttributes) {
        try {
            adocaoService.reprovarAdocao(adocaoId, motivo);
            redirectAttributes.addFlashAttribute("sucesso", "Adoção reprovada.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("erro", "Erro ao reprovar adoção: " + e.getMessage());
        }
        return "redirect:/adocao/listar";
    }

    @GetMapping("/minhas-solicitacoes")
    public String listarMinhasSolicitacoes(Model model, Authentication authentication) {
        Usuarios usuarioLogado = usuarioRepository.findByUserName(authentication.getName())
                .or(() -> usuarioRepository.findByCpf(authentication.getName()))
                .orElseThrow(() -> new IllegalArgumentException("Usuário autenticado não encontrado."));

        List<Adocoes> minhasAdocoes = adocaoService.findByUsuarioId(usuarioLogado.getId());
        model.addAttribute("minhasAdocoes", minhasAdocoes);
        return "listagens/minhasSolicitacoes";
    }
}