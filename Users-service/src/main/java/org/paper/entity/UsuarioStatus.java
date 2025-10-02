package org.paper.entity;

public enum UsuarioStatus {
    /**
     * Usuario creado en Keycloak pero aún no completamente configurado
     * (falta asignar rol, enviar email, etc.)
     */
    PENDING,

    /**
     * Usuario completamente activo y funcional
     */
    ACTIVE,

    /**
     * Falló después de múltiples intentos, requiere revisión manual
     */
    FAILED
}