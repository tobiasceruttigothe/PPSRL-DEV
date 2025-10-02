package org.paper.services;

import lombok.extern.slf4j.Slf4j;
import org.paper.entity.Usuario;
import org.paper.entity.UsuarioStatus;
import org.paper.exception.KeycloakException;
import org.paper.repository.UsuarioRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class UsuarioActivacionService {

    private final UsuarioRepository usuarioRepository;
    private final KeycloakAdminService keycloakAdminService;
    private final UsuarioService usuarioService;
    private final EmailVerificationService emailVerificationService;
    private final WebClient webClient;

    // Configuración de reintentos
    private static final int MAX_INTENTOS = 5;
    private static final long BACKOFF_BASE_MINUTES = 1; // 1, 2, 4, 8, 16 minutos

    public UsuarioActivacionService(UsuarioRepository usuarioRepository,
                                    KeycloakAdminService keycloakAdminService,
                                    UsuarioService usuarioService,
                                    EmailVerificationService emailVerificationService,
                                    WebClient webClient) {
        this.usuarioRepository = usuarioRepository;
        this.keycloakAdminService = keycloakAdminService;
        this.usuarioService = usuarioService;
        this.emailVerificationService = emailVerificationService;
        this.webClient = webClient;
    }

    /**
     * Job que se ejecuta cada 1 minuto para procesar usuarios PENDING
     */
    @Scheduled(fixedRate = 60000) // 60,000 ms = 1 minuto
    @Transactional
    public void procesarUsuariosPendientes() {
        List<Usuario> pendientes = usuarioRepository.findByStatus(UsuarioStatus.PENDING);

        if (pendientes.isEmpty()) {
            log.trace("No hay usuarios pendientes para procesar");
            return;
        }

        log.info("Procesando {} usuarios pendientes", pendientes.size());

        for (Usuario usuario : pendientes) {
            // Verificar si debe reintentar (backoff exponencial)
            if (!debeReintentar(usuario)) {
                log.debug("Usuario {} aún en backoff, saltando", usuario.getId());
                continue;
            }

            procesarUsuario(usuario);
        }
    }

    /**
     * Determina si debe reintentar según backoff exponencial
     */
    private boolean debeReintentar(Usuario usuario) {
        if (usuario.getUltimoIntento() == null) {
            return true; // Primer intento
        }

        // Calcular el delay según el número de intentos (backoff exponencial)
        long backoffMinutes = (long) Math.pow(2, usuario.getIntentosActivacion()) * BACKOFF_BASE_MINUTES;
        LocalDateTime nextRetry = usuario.getUltimoIntento().plusMinutes(backoffMinutes);

        return LocalDateTime.now().isAfter(nextRetry);
    }

    /**
     * Procesa un usuario individual
     */
    @Transactional
    public void procesarUsuario(Usuario usuario) {
        log.info("Procesando usuario {} (intento {}/{})",
                usuario.getId(), usuario.getIntentosActivacion() + 1, MAX_INTENTOS);

        usuario.setUltimoIntento(LocalDateTime.now());
        usuario.setIntentosActivacion(usuario.getIntentosActivacion() + 1);

        try {
            String token = keycloakAdminService.getAdminToken();
            String userId = usuario.getId().toString();

            // 1. Obtener información del usuario desde Keycloak
            log.debug("Obteniendo información del usuario {} desde Keycloak", userId);
            Map<String, Object> keycloakUser = obtenerDatosUsuarioKeycloak(userId, token);

            String username = (String) keycloakUser.get("username");
            String email = (String) keycloakUser.get("email");

            if (email == null || email.isEmpty()) {
                throw new IllegalStateException("El usuario no tiene email configurado en Keycloak");
            }

            // 2. Asignar rol INTERESADO
            log.debug("Asignando rol INTERESADO a usuario {}", userId);
            usuarioService.cambiarRolUsuario(userId, "INTERESADO", token);

            // 3. Enviar email de verificación con tu servicio
            try {
                log.debug("Generando token de verificación y enviando email a {}", email);
                emailVerificationService.createAndSendVerification(userId, username, email);
                log.info("Email de verificación enviado correctamente a {}", email);
            } catch (Exception emailEx) {
                log.warn("No se pudo enviar email a {}: {}. Marcando usuario como activo de todas formas.",
                        email, emailEx.getMessage());
                // No falla por el email, pero registra el error
                // Podrías agregar un flag "emailEnviado" si querés trackear esto
            }

            // 4. Marcar como ACTIVE
            usuario.setStatus(UsuarioStatus.ACTIVE);
            usuario.setMotivoFallo(null);
            usuarioRepository.save(usuario);

            log.info("Usuario {} activado correctamente", userId);

        } catch (Exception e) {
            log.error("Error al procesar usuario {} (intento {}/{}): {}",
                    usuario.getId(), usuario.getIntentosActivacion(), MAX_INTENTOS, e.getMessage(), e);

            // Si alcanzó el máximo de intentos, marcar como FAILED
            if (usuario.getIntentosActivacion() >= MAX_INTENTOS) {
                usuario.setStatus(UsuarioStatus.FAILED);
                usuario.setMotivoFallo(e.getClass().getSimpleName() + ": " + e.getMessage());
                log.error("Usuario {} marcado como FAILED después de {} intentos. Motivo: {}",
                        usuario.getId(), MAX_INTENTOS, usuario.getMotivoFallo());
            }

            usuarioRepository.save(usuario);
        }
    }

    /**
     * Obtiene los datos del usuario desde Keycloak (username y email)
     */
    private Map<String, Object> obtenerDatosUsuarioKeycloak(String userId, String token) {
        try {
            Map<String, Object> user = webClient.get()
                    .uri("/admin/realms/tesina/users/{id}", userId)
                    .header("Authorization", "Bearer " + token)
                    .retrieve()
                    .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                    .block();

            if (user == null) {
                throw new KeycloakException("obtener usuario", "Respuesta vacía de Keycloak");
            }

            return user;
        } catch (Exception e) {
            log.error("Error al obtener datos del usuario {} desde Keycloak: {}", userId, e.getMessage());
            throw new KeycloakException("obtener datos usuario", "No se pudo obtener información del usuario", e);
        }
    }

    /**
     * Método manual para reintentar usuarios fallidos (endpoint admin)
     */
    @Transactional
    public void reintentarUsuarioFallido(String userId) {
        Usuario usuario = usuarioRepository.findById(java.util.UUID.fromString(userId))
                .orElseThrow(() -> new org.paper.exception.UsuarioNotFoundException(userId));

        if (usuario.getStatus() != UsuarioStatus.FAILED) {
            throw new IllegalArgumentException("El usuario no está en estado FAILED");
        }

        log.info("Reintento manual solicitado para usuario {}", userId);

        // Resetear intentos y estado
        usuario.setStatus(UsuarioStatus.PENDING);
        usuario.setIntentosActivacion(0);
        usuario.setUltimoIntento(null);
        usuario.setMotivoFallo(null);
        usuarioRepository.save(usuario);

        // Procesar inmediatamente
        procesarUsuario(usuario);
    }
}