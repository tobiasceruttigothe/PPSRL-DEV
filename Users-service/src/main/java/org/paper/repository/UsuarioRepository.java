package org.paper.repository;

import org.paper.entity.Usuario;
import org.paper.entity.UsuarioStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, UUID> {

    /**
     * Busca usuarios en estado PENDING para procesarlos
     */
    List<Usuario> findByStatus(UsuarioStatus status);

    /**
     * Busca usuarios PENDING que no hayan sido intentados recientemente
     * (para evitar reintentos muy seguidos)
     */
    List<Usuario> findByStatusAndUltimoIntentoIsNull(UsuarioStatus status);

    /**
     * Busca usuarios FAILED para revisión manual
     */
    List<Usuario> findByStatusOrderByFechaRegistroDesc(UsuarioStatus status);
}