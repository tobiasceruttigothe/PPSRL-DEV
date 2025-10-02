package org.paper.exception;

public class KeycloakException extends RuntimeException {

    private final String operation;
    private final Integer statusCode;

    public KeycloakException(String operation, String message) {
        super(String.format("Error en Keycloak [%s]: %s", operation, message));
        this.operation = operation;
        this.statusCode = null;
    }

    public KeycloakException(String operation, String message, Throwable cause) {
        super(String.format("Error en Keycloak [%s]: %s", operation, message), cause);
        this.operation = operation;
        this.statusCode = null;
    }

    public KeycloakException(String operation, Integer statusCode, String message) {
        super(String.format("Error en Keycloak [%s] (HTTP %d): %s", operation, statusCode, message));
        this.operation = operation;
        this.statusCode = statusCode;
    }

    public String getOperation() {
        return operation;
    }

    public Integer getStatusCode() {
        return statusCode;
    }
}