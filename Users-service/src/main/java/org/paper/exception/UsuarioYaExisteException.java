package org.paper.exception;

public class UsuarioYaExisteException extends RuntimeException {

    private final String username;

    public UsuarioYaExisteException(String username) {
        super(String.format("El usuario '%s' ya existe", username));
        this.username = username;
    }

    public UsuarioYaExisteException(String username, Throwable cause) {
        super(String.format("El usuario '%s' ya existe", username), cause);
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}