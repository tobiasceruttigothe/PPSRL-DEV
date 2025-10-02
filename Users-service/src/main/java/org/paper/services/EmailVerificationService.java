package org.paper.services;

import lombok.extern.slf4j.Slf4j;
import org.paper.security.JwtUtil;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EmailVerificationService {

    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final KeycloakAdminService keycloakAdminService;

    public EmailVerificationService(JwtUtil jwtUtil,
                                    EmailService emailService,
                                    KeycloakAdminService keycloakAdminService) {
        this.jwtUtil = jwtUtil;
        this.emailService = emailService;
        this.keycloakAdminService = keycloakAdminService;
    }

    // Llamar justo al final de crearUsuario
    public void createAndSendVerification(String userId, String username, String email) {
        String token = jwtUtil.generateVerificationToken(userId, email);
        emailService.enviarEmailVerificacion(email, username, token);
        log.info("Token de verificación generado y email enviado para userId {}", userId);
    }

    // Endpoint de verificación llamará a esto
    public void verifyTokenAndMarkEmail(String token) {
        String userId = jwtUtil.validateAndGetUserId(token);
        String adminToken = keycloakAdminService.getAdminToken();
        keycloakAdminService.marcarEmailComoVerificado(userId, adminToken);
        log.info("Usuario {} marcado como email verificado en Keycloak", userId);
    }
}
