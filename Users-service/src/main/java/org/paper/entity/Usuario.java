package org.paper.entity;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "usuarios")
public class Usuario {

    @Id
    private UUID id;

    @Column(nullable = false)
    private LocalDateTime fechaRegistro;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UsuarioStatus status;

    @Column(nullable = false)
    private Integer intentosActivacion;

    @Column
    private LocalDateTime ultimoIntento;

    @Column
    private String motivoFallo; // Para saber por qué falló (debugging)

    /**
     * Constructor para crear usuario nuevo
     */
    public Usuario(UUID id) {
        this.id = id;
        this.fechaRegistro = LocalDateTime.now();
        this.status = UsuarioStatus.PENDING;
        this.intentosActivacion = 0;
        this.ultimoIntento = null;
        this.motivoFallo = null;
    }
}


