package bdTrabalho.OngAplication.security;

import bdTrabalho.OngAplication.model.Usuarios;
import bdTrabalho.OngAplication.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.LocalDateTime;

/**
 * Pré-vincula, pelo "sub", os dois usuários de teste do auth-server.
 * A aplicação NÃO conhece (nem guarda) senha alguma: as senhas existem só no provedor.
 */
@Configuration
@RequiredArgsConstructor
public class DataSeederConfig {

    private final UsuarioRepository usuarioRepository;
    private final OidcProperties props;

    @Bean
    public CommandLineRunner seedOidcUsers() {
        return args -> {
            seed("sub-admin-001", "admin@ong.local", "Administrador ONG", "admin");
            seed("sub-user-002", "operador@ong.local", "Operador Balcão", "user");
        };
    }

    private void seed(String sub, String userName, String nome, String role) {
        if (usuarioRepository.findByOidcSub(sub).isPresent()) {
            return;
        }
        Usuarios u = new Usuarios();
        u.setUserName(userName);
        u.setFullName(nome);
        u.setNome(nome);
        u.setOidcSub(sub);
        u.setOidcIssuer(props.issuer());
        u.setRole(role);
        u.setCreatedAt(LocalDateTime.now());
        u.setDataCadastro(LocalDateTime.now());
        usuarioRepository.save(u);
    }
}
