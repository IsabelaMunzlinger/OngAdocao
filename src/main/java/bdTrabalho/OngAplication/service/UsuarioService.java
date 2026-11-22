package bdTrabalho.OngAplication.service;

import bdTrabalho.OngAplication.dto.UsuarioDTO;
import bdTrabalho.OngAplication.model.Usuarios;
import bdTrabalho.OngAplication.repository.UsuarioRepository;
import bdTrabalho.OngAplication.validator.UsuarioValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final UsuarioValidator usuarioValidator;

    @Transactional
    public Usuarios salvar(UsuarioDTO usuarioDTO) {
        String cpfLimpo = usuarioDTO.cpf().replaceAll("[^0-9]", "");

        if (usuarioDTO.id() == null || usuarioDTO.id() == 0) {
            usuarioValidator.validarNovoUsuario(usuarioDTO);

            Usuarios novoUsuario = usuarioDTO.toEntity();
            novoUsuario.setCpf(cpfLimpo);
            novoUsuario.setUserName(usuarioDTO.userName().trim());
            return usuarioRepository.save(novoUsuario);

        } else {
            usuarioValidator.validarEdicaoUsuario(usuarioDTO);

            Usuarios usuarioExistente = usuarioRepository.findById(usuarioDTO.id())
                    .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado para o ID: " + usuarioDTO.id()));

            usuarioExistente.setNome(usuarioDTO.nome());
            usuarioExistente.setFullName(usuarioDTO.nome());
            usuarioExistente.setCpf(cpfLimpo);
            usuarioExistente.setDataNascimento(usuarioDTO.dataNascimento());
            usuarioExistente.setGenero(usuarioDTO.genero());
            usuarioExistente.setFoto(usuarioDTO.foto());

            return usuarioRepository.save(usuarioExistente);
        }
    }

    public List<Usuarios> findAll() {
        return usuarioRepository.findAllByOrderByNomeAsc();
    }

    public Optional<Usuarios> findById(int id) {
        return usuarioRepository.findById(id);
    }

    @Transactional
    public void excluirPorId(Integer id) {
        Usuarios usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Usuário com ID " + id + " não encontrado."));

        usuarioValidator.validateForDeletion(usuario);
        usuarioRepository.deleteById(id);
    }
}