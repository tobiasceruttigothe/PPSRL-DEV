package org.paper.controllers;

import lombok.extern.slf4j.Slf4j;
import org.paper.services.EmailVerificationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    private final EmailVerificationService verificationService;

    public AuthController(EmailVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    // El frontend hará POST (o GET) a este endpoint con token
    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String token) {
        try {
            log.info("Verificación de email solicitada");
            verificationService.verifyTokenAndMarkEmail(token);
            return ResponseEntity.ok("Email verificado correctamente");
        } catch (Exception e) {
            log.error("Error verificando token: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("Token inválido o expirado");
        }
    }
}
