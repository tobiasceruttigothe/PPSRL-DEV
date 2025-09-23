package org.paper.services;


import org.paper.DTO.UsuarioDAO;
import org.paper.entity.Usuario;
import org.paper.repository.UsuarioRepository;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class UsuarioService {

    private final KeycloakAdminService keycloakAdminService;
    private final RestTemplate restTemplate;
    private final UsuarioRepository usuarioRepository;

    public UsuarioService(KeycloakAdminService keycloakAdminService,
                          UsuarioRepository usuarioRepository,
                          RestTemplate restTemplate) {
        this.keycloakAdminService = keycloakAdminService;
        this.usuarioRepository = usuarioRepository;
        this.restTemplate = restTemplate;
    }

    public ResponseEntity<String> crearUsuario(UsuarioDAO usuario) {
        String token = keycloakAdminService.getAdminToken();
        String userId = null;

        try {
            log.info("Iniciando creación de usuario en Keycloak: {}", usuario.getUsername());

            // 1. Crear usuario en Keycloak
            String jsonBody = String.format(
                    "{ \"username\":\"%s\", \"enabled\":%b, \"firstName\":\"%s\", \"lastName\":\"%s\", \"email\":\"%s\", \"emailVerified\":%b }",
                    usuario.getUsername(),
                    usuario.isEnabled(),
                    usuario.getFirstName(),
                    usuario.getLastName(),
                    usuario.getEmail(),
                    usuario.isEmailVerified()
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(token);

            HttpEntity<String> request = new HttpEntity<>(jsonBody, headers);
            String url = "http://localhost:8080/admin/realms/tesina/users";
            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("Usuario creado en Keycloak: {}", usuario.getUsername());

                // 2. Obtener UUID desde Keycloak
                userId = obtenerUserId(usuario.getUsername(), token);
                if (userId == null) {
                    throw new RuntimeException("No se pudo obtener el UUID del usuario en Keycloak");
                }

                // 3. Asignar password (si falla, rollback)
                if (usuario.getPassword() != null) {
                    try {
                        asignarPassword(usuario, token, userId);
                        log.info("Password asignada al usuario: {}", usuario.getUsername());
                    } catch (Exception e) {
                        log.error("Error al asignar password, eliminando usuario en Keycloak", e);
                        eliminarUsuarioEnKeycloak(userId, token);
                        throw new RuntimeException("Fallo asignando password: " + e.getMessage());
                    }
                }

                // 4. Guardar en Postgres
                Usuario entity = new Usuario();
                entity.setId(UUID.fromString(userId));
                entity.setFechaRegistro(LocalDateTime.now());
                usuarioRepository.save(entity);
                log.info("Usuario guardado en Postgres con ID {}", userId);

            } else {
                throw new RuntimeException("Error al crear usuario en Keycloak: " + response.getStatusCode());
            }

            return response;

        } catch (Exception e) {
            if (userId != null) {
                log.warn("Rollback: eliminando usuario {} en Keycloak por fallo en Postgres", userId);
                eliminarUsuarioEnKeycloak(userId, token);
            }
            log.error("Error al crear usuario: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al crear usuario: " + e.getMessage());
        }
    }

    private void asignarPassword(UsuarioDAO usuario, String token, String userId) {
        String passwordUrl = "http://localhost:8080/admin/realms/tesina/users/" + userId + "/reset-password";
        String passwordJson = String.format("{\"type\":\"password\",\"value\":\"%s\",\"temporary\":false}", usuario.getPassword());

        HttpHeaders pwdHeaders = new HttpHeaders();
        pwdHeaders.setContentType(MediaType.APPLICATION_JSON);
        pwdHeaders.setBearerAuth(token);

        HttpEntity<String> pwdRequest = new HttpEntity<>(passwordJson, pwdHeaders);
        restTemplate.exchange(passwordUrl, HttpMethod.PUT, pwdRequest, String.class);
    }

    private void eliminarUsuarioEnKeycloak(String userId, String token) {
        String url = "http://localhost:8080/admin/realms/tesina/users/" + userId;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        restTemplate.exchange(url, HttpMethod.DELETE, request, String.class);
        log.info("Usuario eliminado en Keycloak: {}", userId);
    }

    private String obtenerUserId(String username, String token) {
        String searchUrl = "http://localhost:8080/admin/realms/tesina/users?username=" + username;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<List> searchResponse = restTemplate.exchange(searchUrl, HttpMethod.GET, entity, List.class);
        List<?> body = searchResponse.getBody();

        if (body == null || body.isEmpty()) {
            log.warn("No se encontró usuario en Keycloak con username: {}", username);
            return null;
        }
        if (body.size() > 1) {
            log.error("Se encontraron múltiples usuarios en Keycloak con el mismo username: {}", username);
            throw new RuntimeException("Más de un usuario encontrado con el username: " + username);
        }

        Map<String, Object> user = (Map<String, Object>) body.get(0);
        return (String) user.get("id");
    }

    /*public ResponseEntity<String> eliminarUsuario(String username) {
        String token = keycloakAdminService.getAdminToken();
        try {
            String userId = obtenerUserId(username, token);
            if (userId == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Usuario no encontrado en Keycloak: " + username);
            }

            eliminarUsuarioEnKeycloak(userId, token);
            usuarioRepository.deleteById(UUID.fromString(userId));
            log.info("Usuario eliminado en Keycloak y Postgres: {}", username);

            return ResponseEntity.ok("Usuario eliminado correctamente");
        } catch (Exception e) {
            log.error("Error al eliminar usuario: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al eliminar usuario: " + e.getMessage());
        }
    }

     */
    public ResponseEntity<String> eliminarUsuario(String username) {
        String token = keycloakAdminService.getAdminToken();
        try {
            String userId = obtenerUserId(username, token);
            if (userId == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Usuario no encontrado en Keycloak: " + username);
            }

            // 1. Recuperar usuario de Postgres (para rollback si falla después)
            Optional<Usuario> usuarioBackup = usuarioRepository.findById(UUID.fromString(userId));

            // 2. Eliminar en Postgres (con try/catch dedicado)
            try {
                usuarioRepository.deleteById(UUID.fromString(userId));
                log.info("Usuario eliminado en Postgres: {}", username);
            } catch (Exception e) {
                log.error("Error eliminando usuario en Postgres, cancelando proceso", e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error al eliminar usuario en Postgres: " + e.getMessage());
            }

            // 3. Eliminar en Keycloak
            try {
                eliminarUsuarioEnKeycloak(userId, token);
                log.info("Usuario eliminado en Keycloak: {}", username);
            } catch (Exception e) {
                log.error("Error al eliminar usuario en Keycloak, intentando rollback en Postgres", e);

                // ⚠️ Rollback → restauramos el registro en Postgres
                usuarioBackup.ifPresent(usuarioRepository::save);

                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Fallo en Keycloak, usuario restaurado en Postgres");
            }

            return ResponseEntity.ok("Usuario eliminado correctamente en Postgres y Keycloak");

        } catch (Exception e) {
            log.error("Error inesperado al eliminar usuario: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al eliminar usuario: " + e.getMessage());
        }
    }



}


