package bdTrabalho.OngAplication.model;

import bdTrabalho.OngAplication.model.ENUM.Genero;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@Entity
@Table(name = "Usuarios")
public class Usuarios {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(name = "user_name", unique = true, length = 150)
    private String userName;

    @Column(name = "full_name", length = 255)
    private String fullName;

    @Column(name = "oidc_sub", unique = true, length = 255)
    private String oidcSub;

    /** Emissor (iss) do sub: o vínculo com o provedor é iss + sub (OIDC Core §5.7). */
    @Column(name = "oidc_issuer", length = 255)
    private String oidcIssuer;

    @Column(name = "role", length = 50)
    private String role;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "nome", nullable = false, length = 255)
    private String nome;

    @Column(name = "cpf", unique = true, length = 11)
    private String cpf;

    @Column(name = "data_nascimento")
    private LocalDate dataNascimento;

    @Enumerated(EnumType.STRING)
    @Column(name = "genero", length = 20)
    private Genero genero;

    @Column(name = "tipo", length = 1)
    private char tipo = 'U';

    @Column(name = "data_cadastro", nullable = false)
    private LocalDateTime dataCadastro = LocalDateTime.now();

    @Column(name = "foto", length = 1024)
    private String foto;

    @OneToMany(mappedBy = "usuario", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<Enderecos> enderecos = new ArrayList<>();

    @OneToMany(mappedBy = "usuario", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<Contatos> contatos = new ArrayList<>();

    @OneToMany(mappedBy = "usuario", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<Adocoes> adocoes = new ArrayList<>();
}