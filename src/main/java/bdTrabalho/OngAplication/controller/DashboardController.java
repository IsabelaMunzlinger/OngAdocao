package bdTrabalho.OngAplication.controller;

import bdTrabalho.OngAplication.service.AnimalService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class DashboardController {

    private final AnimalService animalService;

    @GetMapping({"/", "/menuPrincipal"})
    public String showDashboard(Model model, Authentication authentication) {
        if (authentication != null && authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(r -> r.equals("ROLE_ADOTANTE"))) {
            return "redirect:/adocao";
        }

        model.addAttribute("totalDeAnimais", animalService.countTotal());
        model.addAttribute("animaisDisponiveis", animalService.countDisponiveis());
        return "index";
    }
}