package org.paper.exception;

public class UsuarioNotFoundException extends RuntimeException {

    private final String username;

    public UsuarioNotFoundException(String username) {
        super(String.format("Usuario '%s' no encontrado", username));
        this.username = username;
    }

    public UsuarioNotFoundException(String username, Throwable cause) {
        super(String.format("Usuario '%s' no encontrado", username), cause);
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}