package org.paper.services;

import lombok.extern.slf4j.Slf4j;

import org.paper.DTO.UsuarioDTO;
import org.paper.entity.Usuario;
import org.paper.repository.UsuarioRepository;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Service
public class UsuarioService {

    private final KeycloakAdminService keycloakAdminService;
    private final UsuarioRepository usuarioRepository;
    private final WebClient webClient;

    public UsuarioService(KeycloakAdminService keycloakAdminService,
                          UsuarioRepository usuarioRepository,
                          WebClient webClient) {
        this.keycloakAdminService = keycloakAdminService;
        this.usuarioRepository = usuarioRepository;
        this.webClient = webClient;
    }

    @Transactional
    public ResponseEntity<String> crearUsuario(UsuarioDTO usuario) {
        String token = keycloakAdminService.getAdminToken();
        String userId = null;

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

            ResponseEntity<String> response = webClient.post()
                    .uri("/admin/realms/tesina/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(jsonBody)
                    .retrieve()
                    .toEntity(String.class)
                    .block();

            if (response.getStatusCode().is2xxSuccessful()) {
                // 2. Obtener UUID
                userId = obtenerUserId(usuario.getUsername(), token);
                if (userId == null) throw new RuntimeException("No se pudo obtener el UUID de Keycloak");

                // 3. Asignar password
                if (usuario.getPassword() != null) {
                    try {
                        asignarPassword(usuario, token, userId);
                    } catch (Exception e) {
                        eliminarUsuarioEnKeycloak(userId, token);
                        throw new RuntimeException("Fallo asignando password: " + e.getMessage());
                    }
                }

                // 4. Guardar en Postgres (protegido por @Transactional)
                Usuario entity = new Usuario();
                entity.setId(UUID.fromString(userId));
                entity.setFechaRegistro(LocalDateTime.now());
                usuarioRepository.save(entity);

                // 5. Asignar rol por defecto (INTERESADO)
                try {
                    asignarRol(userId, "INTERESADO", token);
                } catch (Exception e) {
                    eliminarUsuarioEnKeycloak(userId, token);
                    throw new RuntimeException("Fallo asignando rol: " + e.getMessage());
                }

            } else {
                throw new RuntimeException("Error al crear usuario en Keycloak: " + response.getStatusCode());
            }

            return ResponseEntity.ok("Usuario creado correctamente");

        } catch (Exception e) {
            if (userId != null) {
                eliminarUsuarioEnKeycloak(userId, token);
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al crear usuario: " + e.getMessage());
        }
    }

    private void asignarPassword(UsuarioDTO usuario, String token, String userId) {
        String passwordJson = String.format("{\"type\":\"password\",\"value\":\"%s\",\"temporary\":false}", usuario.getPassword());

        webClient.put()
                .uri("/admin/realms/tesina/users/{id}/reset-password", userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(passwordJson)
                .retrieve()
                .toBodilessEntity()
                .block();
    }

    private void eliminarUsuarioEnKeycloak(String userId, String token) {
        webClient.delete()
                .uri("/admin/realms/tesina/users/{id}", userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .toBodilessEntity()
                .block();
    }

    private String obtenerUserId(String username, String token) {
        List<Map<String, Object>> body = webClient.get()
                .uri("/admin/realms/tesina/users?username={username}", username)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {})
                .collectList()
                .block();

        if (body == null || body.isEmpty()) return null;
        if (body.size() > 1) throw new RuntimeException("Más de un usuario encontrado: " + username);

        return (String) body.get(0).get("id");
    }

    @Transactional
    public ResponseEntity<String> eliminarUsuario(String username) {
        String token = keycloakAdminService.getAdminToken();
        try {
            String userId = obtenerUserId(username, token);
            if (userId == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Usuario no encontrado en Keycloak: " + username);
            }

            Optional<Usuario> backup = usuarioRepository.findById(UUID.fromString(userId));

            // Eliminar de Postgres
            usuarioRepository.deleteById(UUID.fromString(userId));

            try {
                eliminarUsuarioEnKeycloak(userId, token);
            } catch (Exception e) {
                // rollback en Postgres
                backup.ifPresent(usuarioRepository::save);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Fallo en Keycloak, usuario restaurado en Postgres");
            }

            return ResponseEntity.ok("Usuario eliminado correctamente");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al eliminar usuario: " + e.getMessage());
        }
    }

    private void asignarRol(String userId, String roleName, String token) {
        Map<String, Object> role = webClient.get()
                .uri("/admin/realms/tesina/roles/{roleName}", roleName)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();

        if (role == null) throw new RuntimeException("Rol no encontrado: " + roleName);

        webClient.post()
                .uri("/admin/realms/tesina/users/{userId}/role-mappings/realm", userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .bodyValue(List.of(role))
                .retrieve()
                .toBodilessEntity()
                .block();
    }


    public ResponseEntity<List<Map<String, Object>>> listarUsuarios() {
        String token = keycloakAdminService.getAdminToken();
        try {
            List<Map<String, Object>> users = webClient.get()
                    .uri("/admin/realms/tesina/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .collectList()
                    .block();

            if (users == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Collections.emptyList());
            }

            return ResponseEntity.ok(users);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.emptyList());
        }
    }
}
