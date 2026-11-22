package bdTrabalho.OngAplication.validator;

import bdTrabalho.OngAplication.dto.UsuarioDTO;
import bdTrabalho.OngAplication.model.Usuarios;
import bdTrabalho.OngAplication.repository.AdocaoRepository;
import bdTrabalho.OngAplication.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UsuarioValidator {

    private final UsuarioRepository usuarioRepository;
    private final AdocaoRepository adocaoRepository;

    public void validarNovoUsuario(UsuarioDTO dto) {
        String cpfLimpo = dto.cpf().replaceAll("[^0-9]", "");
        if (usuarioRepository.existsByCpf(cpfLimpo)) {
            throw new IllegalArgumentException("O CPF informado já está cadastrado.");
        }
        if (dto.userName() != null && usuarioRepository.existsByUserName(dto.userName().trim())) {
            throw new IllegalArgumentException("O nome de usuário informado já está em uso.");
        }
        if (dto.oidcSub() == null || dto.oidcSub().isBlank()) {
            throw new IllegalArgumentException("Informe o identificador (sub) do usuário no provedor de identidade.");
        }
        if (usuarioRepository.existsByOidcSub(dto.oidcSub().trim())) {
            throw new IllegalArgumentException("Este identificador (sub) já está vinculado a outro usuário.");
        }
    }

    public void validarEdicaoUsuario(UsuarioDTO dto) {
        String cpfLimpo = dto.cpf().replaceAll("[^0-9]", "");
        if (usuarioRepository.existsByCpfAndIdNot(cpfLimpo, dto.id())) {
            throw new IllegalArgumentException("O CPF informado já pertence a outro usuário.");
        }
        if (dto.userName() != null && usuarioRepository.existsByUserNameAndIdNot(dto.userName().trim(), dto.id())) {
            throw new IllegalArgumentException("O nome de usuário informado já está em uso.");
        }
        if (dto.oidcSub() != null && !dto.oidcSub().isBlank()
                && usuarioRepository.existsByOidcSubAndIdNot(dto.oidcSub().trim(), dto.id())) {
            throw new IllegalArgumentException("Este identificador (sub) já está vinculado a outro usuário.");
        }
    }

    public void validateForDeletion(Usuarios usuario) {
        long adocoesCount = adocaoRepository.countByUsuarioId(usuario.getId());
        if (adocoesCount > 0) {
            throw new IllegalStateException("Não é possível excluir este usuário, pois ele está associado a " + adocoesCount + " registro(s) de adoção.");
        }
    }
}