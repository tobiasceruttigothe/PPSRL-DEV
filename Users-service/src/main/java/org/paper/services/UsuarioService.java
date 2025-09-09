package org.paper.services;


import org.paper.DTO.UsuarioDAO;
import org.paper.entity.Usuario;
import org.paper.repository.UsuarioRepository;
import org.springframework.http.*;
        import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UsuarioService {

    private final KeycloakAdminService keycloakAdminService;
    private final RestTemplate restTemplate = new RestTemplate();
    private final UsuarioRepository usuarioRepository; // JPA repository

    public UsuarioService(KeycloakAdminService keycloakAdminService, UsuarioRepository usuarioRepository) {
        this.keycloakAdminService = keycloakAdminService;
        this.usuarioRepository = usuarioRepository;
    }

    public ResponseEntity<String> crearUsuario(UsuarioDAO usuario) {
        String token = keycloakAdminService.getAdminToken();
        String userId = null; // lo vamos a usar para rollback

        try {
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
                // 2. Asignar password
                if (usuario.getPassword() != null) {
                    asignarPassword(usuario, token);
                }

                // 3. Obtener UUID desde Keycloak
                userId = obtenerUserId(usuario.getUsername(), token);

                if (userId != null) {
                    // 4. Guardar en Postgres
                    Usuario entity = new Usuario();
                    entity.setId(UUID.fromString(userId));
                    entity.setFechaRegistro(LocalDateTime.now());
                    usuarioRepository.save(entity);
                } else {
                    throw new RuntimeException("No se pudo obtener el UUID del usuario en Keycloak");
                }
            } else {
                throw new RuntimeException("Error al crear usuario en Keycloak: " + response.getStatusCode());
            }

            return response;

        } catch (Exception e) {
            // Rollback: si ya existía en Keycloak pero falló en Postgres, lo eliminamos
            if (userId != null) {
                eliminarUsuarioEnKeycloak(userId, token);
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al crear usuario: " + e.getMessage());
        }
    }
    private void asignarPassword(UsuarioDAO usuario, String token) {
        String userId = obtenerUserId(usuario.getUsername(), token);
        if (userId == null) return;

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
    }

    private String obtenerUserId(String username, String token) {
        String searchUrl = "http://localhost:8080/admin/realms/tesina/users?username=" + username;
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<Object[]> searchResponse = restTemplate.exchange(searchUrl, HttpMethod.GET, entity, Object[].class);
        if (searchResponse.getBody() != null && searchResponse.getBody().length > 0) {
            return (String) ((java.util.LinkedHashMap) searchResponse.getBody()[0]).get("id");
        }
        return null;
    }

    public ResponseEntity<String> eliminarUsuario(String username) {
        String token = keycloakAdminService.getAdminToken();
        try {
            // 1. Buscar el userId en Keycloak
            String userId = obtenerUserId(username, token);
            if (userId == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Usuario no encontrado en Keycloak: " + username);
            }

            // 2. Eliminar en Keycloak
            eliminarUsuarioEnKeycloak(userId, token);

            // 3. Eliminar en Postgres
            usuarioRepository.deleteById(UUID.fromString(userId));

            return ResponseEntity.ok("Usuario eliminado correctamente");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al eliminar usuario: " + e.getMessage());
        }
    }
}


