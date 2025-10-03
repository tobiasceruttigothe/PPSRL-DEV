package org.paper.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.paper.dto.ErrorResponse;
import org.paper.services.EmailVerificationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Slf4j
@Tag(name = "Autenticación", description = "Endpoints públicos de autenticación y verificación")
public class AuthController {

    private final EmailVerificationService verificationService;

    public AuthController(EmailVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @PostMapping("/verify-email")
    @Operation(
            summary = "Verificar email del usuario",
            description = """
            Verifica el email de un usuario usando el token JWT enviado por correo.
            
            **Flujo:**
            1. Usuario recibe email con link: `http://frontend.com/verify-email?token=XXX`
            2. Frontend extrae el token del query param
            3. Frontend llama a este endpoint con el token
            4. Backend valida el token y marca el email como verificado en Keycloak
            
            ⚠️ **Nota:** Este endpoint es público (no requiere autenticación previa).
            
            **Token válido por:** 24 horas
            """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Email verificado correctamente. El usuario ya puede iniciar sesión.",
                    content = @Content(mediaType = "text/plain")
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Token inválido, expirado o mal formado",
                    content = @Content(
                            mediaType = "text/plain",
                            schema = @Schema(example = "Token inválido o expirado")
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Error interno al verificar el email",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))
            )
    })
    public ResponseEntity<String> verifyEmail(
            @Parameter(
                    description = "Token JWT de verificación recibido por email",
                    required = true,
                    example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpYXQiOjE3MDk1ODEyMDAsImV4cCI6MTcwOTY2NzYwMH0.aBcDeFgHiJkLmNoPqRsTuVwXyZ"
            )
            @RequestParam("token") String token) {
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