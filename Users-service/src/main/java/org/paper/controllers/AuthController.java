package org.paper.controllers;

import lombok.extern.slf4j.Slf4j;
import org.paper.services.KeycloakAdminService;
import org.paper.services.VerificationTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    private final VerificationTokenService tokenService;
    private final KeycloakAdminService keycloakAdminService;

    public AuthController(VerificationTokenService tokenService,
                          KeycloakAdminService keycloakAdminService) {
        this.tokenService = tokenService;
        this.keycloakAdminService = keycloakAdminService;
    }

    @PostMapping("/verify-email")
    public ResponseEntity<String> verificarEmail(@RequestParam String token) {
        try {
            log.info("Verificando email con token {}", token);

            String userId = tokenService.validarToken(token);

            String adminToken = keycloakAdminService.getAdminToken();
            keycloakAdminService.marcarEmailComoVerificado(userId, adminToken);

            return ResponseEntity.ok("Email verificado correctamente");
        } catch (Exception e) {
            log.error("Error verificando email: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Token inválido o expirado");
        }
    }
}
