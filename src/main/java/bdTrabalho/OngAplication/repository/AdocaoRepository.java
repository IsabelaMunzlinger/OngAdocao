package bdTrabalho.OngAplication.repository;

import bdTrabalho.OngAplication.model.Adocoes;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AdocaoRepository extends JpaRepository<Adocoes, Integer> {

    Integer countByUsuarioId(Integer usuarioId);

    List<Adocoes> findByUsuarioIdOrderByDataAdocaoDesc(Integer usuarioId);
}