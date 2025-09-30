package org.paper.entity;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "usuarios")
@AllArgsConstructor
@NoArgsConstructor
@Data
public class Usuario {
        @Id
        @Column(nullable = false, unique = true)
        private UUID id;  // el keycloak_id

        @Column(name = "fecha_registro", nullable = false)
        private LocalDateTime fechaRegistro;

}


