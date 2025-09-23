package org.paper.DTO;


import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
//@NoArgsConstructor
@Data
public class UsuarioDTO {
        private String username;
        private String firstName;
        private String lastName;
        private String email;
        private String password;
        private boolean enabled = true;
        private boolean emailVerified = true;
}

