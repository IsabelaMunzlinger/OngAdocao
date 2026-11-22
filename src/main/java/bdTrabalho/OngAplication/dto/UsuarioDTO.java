package bdTrabalho.OngAplication.dto;

import bdTrabalho.OngAplication.model.ENUM.Genero;
import bdTrabalho.OngAplication.model.Usuarios;
import bdTrabalho.OngAplication.validator.dtoValidatorGroup.OnCreate;
import bdTrabalho.OngAplication.validator.dtoValidatorGroup.OnUpdate;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import jakarta.validation.groups.Default;
import org.hibernate.validator.constraints.br.CPF;

import java.time.LocalDate;
import java.time.LocalDateTime;

public record UsuarioDTO(

        Integer id,

        @NotBlank(message = "O nome não pode estar em branco.", groups = {Default.class, OnCreate.class, OnUpdate.class})
        @Size(min = 3, message = "O nome deve ter no mínimo 3 caracteres.", groups = {Default.class, OnCreate.class, OnUpdate.class})
        String nome,

        String userName,

        @NotBlank(message = "O CPF não pode estar em branco.", groups = {Default.class, OnCreate.class, OnUpdate.class})
        @CPF(message = "O CPF fornecido é inválido.", groups = {Default.class, OnCreate.class, OnUpdate.class})
        String cpf,

        @NotNull(message = "A data de nascimento não pode ser nula.", groups = {Default.class, OnCreate.class, OnUpdate.class})
        @Past(message = "A data de nascimento deve ser no passado.", groups = {Default.class, OnCreate.class, OnUpdate.class})
        LocalDate dataNascimento,

        Genero genero,

        String foto,

        @Size(max = 255, message = "O identificador (sub) deve ter no máximo 255 caracteres.", groups = {Default.class, OnCreate.class, OnUpdate.class})
        String oidcSub,

        String role
) {

    public Usuarios toEntity() {
        Usuarios usuario = new Usuarios();
        usuario.setNome(this.nome);
        usuario.setFullName(this.nome);
        usuario.setUserName(this.userName != null ? this.userName.trim() : null);
        usuario.setCpf(this.cpf);
        usuario.setDataNascimento(this.dataNascimento);
        usuario.setGenero(this.genero);
        usuario.setFoto(this.foto);
        usuario.setOidcSub(this.oidcSub != null && !this.oidcSub.isBlank() ? this.oidcSub.trim() : null);
        usuario.setRole(this.role != null && !this.role.isBlank() ? this.role : "adotante");
        usuario.setCreatedAt(LocalDateTime.now());
        usuario.setDataCadastro(LocalDateTime.now());
        return usuario;
    }

    public static UsuarioDTO fromEntity(Usuarios usuario) {
        return new UsuarioDTO(
                usuario.getId(),
                usuario.getNome(),
                usuario.getUserName(),
                usuario.getCpf(),
                usuario.getDataNascimento(),
                usuario.getGenero(),
                usuario.getFoto(),
                usuario.getOidcSub(),
                usuario.getRole()
        );
    }
}