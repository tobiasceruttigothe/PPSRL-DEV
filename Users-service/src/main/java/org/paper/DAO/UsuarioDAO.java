package org.paper.DAO;


import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
//@NoArgsConstructor
@Data
public class UsuarioDAO {
        private String username;
        private String firstName;
        private String lastName;
        private String email;
        private String password;
        private boolean enabled = true;
        private boolean emailVerified = false;
}
