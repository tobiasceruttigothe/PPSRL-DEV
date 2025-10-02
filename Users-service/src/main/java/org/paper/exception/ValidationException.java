package org.paper.exception;

import java.util.HashMap;
import java.util.Map;

public class ValidationException extends RuntimeException {

    private final Map<String, String> errors;

    public ValidationException(String message) {
        super(message);
        this.errors = new HashMap<>();
    }

    public ValidationException(String field, String error) {
        super(String.format("Error de validación en '%s': %s", field, error));
        this.errors = new HashMap<>();
        this.errors.put(field, error);
    }

    public ValidationException(Map<String, String> errors) {
        super("Errores de validación múltiples");
        this.errors = errors;
    }

    public Map<String, String> getErrors() {
        return errors;
    }
}