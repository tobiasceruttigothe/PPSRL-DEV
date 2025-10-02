package org.paper.exception;

public class EmailException extends RuntimeException {

    private final String recipient;

    public EmailException(String recipient, String message) {
        super(String.format("Error al enviar email a '%s': %s", recipient, message));
        this.recipient = recipient;
    }

    public EmailException(String recipient, String message, Throwable cause) {
        super(String.format("Error al enviar email a '%s': %s", recipient, message), cause);
        this.recipient = recipient;
    }

    public String getRecipient() {
        return recipient;
    }
}