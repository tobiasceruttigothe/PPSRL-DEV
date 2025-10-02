package org.paper.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UsuarioCreateDTO {

    @NotBlank(message = "El username es obligatorio")
    @Size(min = 5, max = 50, message = "El username debe tener entre 5 y 50 caracteres")
    private String username;

    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email debe tener un formato válido")
    @Size(max = 50, message = "El email no puede superar los 50 caracteres")
    private String email;

    @NotBlank(message = "La razón social es obligatoria")
    @Size(max = 100, message = "La razón social no puede superar los 100 caracteres")
    private String razonSocial;

    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, max = 50, message = "La contraseña debe tener entre 8 y 50 caracteres")
    private String password;

    @Builder.Default
    private boolean enabled = true;

    @Builder.Default
    private boolean emailVerified = false;
}