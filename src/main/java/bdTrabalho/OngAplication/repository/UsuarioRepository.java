package bdTrabalho.OngAplication.repository;

import bdTrabalho.OngAplication.model.Usuarios;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuarios, Integer> {
    boolean existsByCpf(String cpf);

    boolean existsByCpfAndIdNot(String cpf, int id);

    boolean existsByUserName(String userName);

    boolean existsByUserNameAndIdNot(String userName, int id);

    List<Usuarios> findAllByOrderByNomeAsc();

    Optional<Usuarios> findByOidcSub(String oidcSub);

    boolean existsByOidcSub(String oidcSub);

    boolean existsByOidcSubAndIdNot(String oidcSub, int id);

    Optional<Usuarios> findByUserName(String userName);

    Optional<Usuarios> findByCpf(String cpf);
}