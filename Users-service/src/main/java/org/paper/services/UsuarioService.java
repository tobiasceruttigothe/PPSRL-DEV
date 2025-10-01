package org.paper.services;

import lombok.extern.slf4j.Slf4j;

import org.paper.DTO.UsuarioCreateDTO;
import org.paper.DTO.UsuarioResponseDTO;
import org.paper.entity.Usuario;
import org.paper.repository.UsuarioRepository;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

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
    public ResponseEntity<String> crearUsuario(UsuarioCreateDTO usuario) {
        log.info("Iniciando creación de usuario: {}", usuario.getUsername());
        String token = keycloakAdminService.getAdminToken();
        String userId = null;
        boolean usuarioExisteEnKeycloak = false;

        try {
            // 1. Crear usuario en Keycloak
            log.debug("Creando usuario en Keycloak");
            String jsonBody = String.format(
                    "{ \"username\":\"%s\", \"enabled\":%b, \"email\":\"%s\", \"emailVerified\":%b, \"attributes\": { \"razonSocial\": [\"%s\"] } }",
                    usuario.getUsername(),
                    usuario.isEnabled(),
                    usuario.getEmail(),
                    usuario.isEmailVerified(),
                    usuario.getRazonSocial()
            );

            ResponseEntity<String> response = webClient.post()
                    .uri("/admin/realms/tesina/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(jsonBody)
                    .retrieve()
                    .toEntity(String.class)
                    .block();

            if (!response.getStatusCode().is2xxSuccessful()) {
                log.error("Error al crear usuario en Keycloak: {}", response.getStatusCode());
                throw new RuntimeException("Error al crear usuario en Keycloak: " + response.getStatusCode());
            }

            // 2. Obtener UUID
            log.debug("Obteniendo UUID del usuario");
            userId = obtenerUserId(usuario.getUsername(), token);
            if (userId == null) {
                log.error("No se pudo obtener el UUID de Keycloak para: {}", usuario.getUsername());
                throw new RuntimeException("No se pudo obtener el UUID de Keycloak");
            }

            usuarioExisteEnKeycloak = true;
            log.info("Usuario creado en Keycloak con ID: {}", userId);

            // 3. Asignar password
            if (usuario.getPassword() != null) {
                log.debug("Asignando contraseña");
                asignarPassword(usuario, token, userId);
            }

            // 4. Guardar en Postgres (protegido por @Transactional)
            log.debug("Guardando usuario en base de datos");
            Usuario entity = new Usuario();
            entity.setId(UUID.fromString(userId));
            entity.setFechaRegistro(LocalDateTime.now());
            usuarioRepository.save(entity);

            // 5. Asignar rol por defecto (INTERESADO)
            log.debug("Asignando rol INTERESADO");
            cambiarRolUsuario(userId, "INTERESADO", token);

            // 6. Enviar email de verificación
            log.debug("Enviando email de verificación");
            enviarEmailVerificacion(userId, token);

            log.info("Usuario {} creado correctamente", usuario.getUsername());
            return ResponseEntity.ok("Usuario creado correctamente. Se envió mail de verificación.");

        } catch (Exception e) {
            log.error("Error durante la creación del usuario {}: {}",
                    usuario.getUsername(), e.getMessage(), e);

            // Solo intentar eliminar si el usuario fue creado en Keycloak
            if (usuarioExisteEnKeycloak && userId != null) {
                log.warn("Intentando rollback: eliminar usuario {} de Keycloak", userId);
                try {
                    eliminarUsuarioEnKeycloak(userId, token);
                    log.info("Rollback exitoso: usuario eliminado de Keycloak");
                } catch (Exception deleteEx) {
                    log.error("Error durante el rollback al eliminar usuario de Keycloak: {}",
                            deleteEx.getMessage(), deleteEx);
                    // No lanzar excepción aquí, ya estamos en manejo de error
                }
            }

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al crear usuario: " + e.getMessage());
        }
    }

    private void enviarEmailVerificacion(String userId, String token) {
        try {
            log.debug("Enviando email de verificación a usuario: {}", userId);
            webClient.put()
                    .uri("/admin/realms/tesina/users/{userId}/send-verify-email", userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
            log.debug("Email de verificación enviado correctamente");
        } catch (WebClientResponseException e) {
            log.error("Error al enviar email. Status: {}, Body: {}, Headers: {}",
                    e.getStatusCode(),
                    e.getResponseBodyAsString(),
                    e.getHeaders());
            throw new RuntimeException("No se pudo enviar el mail de verificación: " + e.getMessage(), e);
        }
    }
    // En UsuarioService
    public void verificarEmailUsuario(String userId) {
        String token = keycloakAdminService.getAdminToken();

        // Marcar email como verificado
        String jsonBody = "{ \"emailVerified\": true }";

        webClient.put()
                .uri("/admin/realms/tesina/users/{id}", userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(jsonBody)
                .retrieve()
                .toBodilessEntity()
                .block();

        log.info("Email verificado para usuario: {}", userId);
    }

    private void asignarPassword(UsuarioCreateDTO usuario, String token, String userId) {
        log.debug("Asignando password para usuario: {}", userId);
        String passwordJson = String.format(
                "{\"type\":\"password\",\"value\":\"%s\",\"temporary\":false}",
                usuario.getPassword()
        );

        try {
            webClient.put()
                    .uri("/admin/realms/tesina/users/{id}/reset-password", userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(passwordJson)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
            log.debug("Password asignado correctamente");
        } catch (Exception e) {
            log.error("Error al asignar password: {}", e.getMessage(), e);
            throw new RuntimeException("Error al asignar password: " + e.getMessage(), e);
        }
    }
//revisar public
    public void eliminarUsuarioEnKeycloak(String userId, String token) {
        webClient.delete()
                .uri("/admin/realms/tesina/users/{id}", userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .toBodilessEntity()
                .block();
    }
//revisar
    public String prueba(String username) {
        String token = keycloakAdminService.getAdminToken();
        return obtenerUserId(username, token);
    }
//revisar, sacar public
    public String obtenerUserId(String username, String token) {
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

   /* @Transactional
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

    */

    @Transactional
    public ResponseEntity<String> eliminarUsuario(String username) {
        String token = keycloakAdminService.getAdminToken();
        log.debug("Iniciando proceso de eliminación para usuario: {}", username);

        try {
            String userId = obtenerUserId(username, token);
            if (userId == null) {
                log.warn("Usuario no encontrado en Keycloak: {}", username);
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Usuario no encontrado en Keycloak: " + username);
            }

            log.debug("Usuario {} encontrado con ID: {}", username, userId);

            Optional<Usuario> backup = usuarioRepository.findById(UUID.fromString(userId));
            log.debug("Backup del usuario en Postgres creado: {}", backup.isPresent());

            // Eliminar de Postgres
            usuarioRepository.deleteById(UUID.fromString(userId));
            log.info("Usuario {} eliminado de Postgres con ID: {}", username, userId);

            try {
                eliminarUsuarioEnKeycloak(userId, token);
                log.info("Usuario {} eliminado correctamente de Keycloak con ID: {}", username, userId);
            } catch (Exception e) {
                log.error("Error eliminando usuario {} en Keycloak. Restaurando backup en Postgres. Detalle: {}", username, e.getMessage(), e);
                backup.ifPresent(usuario -> {
                    usuarioRepository.save(usuario);
                    log.warn("Usuario {} restaurado en Postgres tras fallo en Keycloak", username);
                });
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Fallo en Keycloak, usuario restaurado en Postgres");
            }

            log.debug("Proceso de eliminación completado para usuario: {}", username);
            return ResponseEntity.ok("Usuario eliminado correctamente");
        } catch (Exception e) {
            log.error("Error inesperado al eliminar usuario {}. Detalle: {}", username, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al eliminar usuario: " + e.getMessage());
        }
    }


    public void cambiarRolUsuarioConToken(String userId, String nuevoRol) {
        String token = keycloakAdminService.getAdminToken();
        cambiarRolUsuario(userId, nuevoRol, token);
    }
    public void cambiarRolUsuario(String userId, String nuevoRol, String token) {
        log.debug("Iniciando cambio de rol para usuario con ID: {}. Nuevo rol: {}", userId, nuevoRol);

        try {
            // 1. Obtener todos los roles actuales del usuario
            List<Map<String, Object>> rolesActuales = webClient.get()
                    .uri("/admin/realms/tesina/users/{userId}/role-mappings/realm", userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .collectList()
                    .block();

            log.debug("Roles actuales obtenidos para usuario {}: {}", userId, rolesActuales);

            if (rolesActuales != null && !rolesActuales.isEmpty()) {
                // 2. Eliminar roles actuales
                log.info("Eliminando {} roles actuales del usuario {}", rolesActuales.size(), userId);
                webClient.method(HttpMethod.DELETE)
                        .uri("/admin/realms/tesina/users/{userId}/role-mappings/realm", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .bodyValue(rolesActuales)
                        .retrieve()
                        .toBodilessEntity()
                        .block();
                log.debug("Roles actuales eliminados para usuario {}", userId);
            } else {
                log.debug("El usuario {} no tenía roles previos asignados", userId);
            }

            // 3. Obtener el rol nuevo
            log.debug("Obteniendo rol {} desde Keycloak", nuevoRol);
            Map<String, Object> role = webClient.get()
                    .uri("/admin/realms/tesina/roles/{roleName}", nuevoRol)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .block();

            if (role == null) {
                log.error("No se encontró el rol {} en Keycloak", nuevoRol);
                throw new RuntimeException("Rol no encontrado: " + nuevoRol);
            }

            log.debug("Rol {} obtenido correctamente: {}", nuevoRol, role);

            // 4. Asignar el nuevo rol
            log.info("Asignando rol {} al usuario {}", nuevoRol, userId);
            webClient.post()
                    .uri("/admin/realms/tesina/users/{userId}/role-mappings/realm", userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .bodyValue(List.of(role))
                    .retrieve()
                    .toBodilessEntity()
                    .block();

            log.info("Rol {} asignado correctamente al usuario {}", nuevoRol, userId);

        } catch (Exception e) {
            log.error("Error al cambiar rol del usuario {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Fallo cambiando rol del usuario: " + e.getMessage(), e);
        }
    }

    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuarios() {
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

            List<UsuarioResponseDTO> response = new ArrayList<>();
            for (Map<String, Object> user : users) {
                String userId = (String) user.get("id");

                // Consultar roles de cada usuario
                List<String> roles = webClient.get()
                        .uri("/admin/realms/tesina/users/{id}/role-mappings/realm", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .retrieve()
                        .bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {})
                        .map(role -> (String) role.get("name"))
                        .collectList()
                        .block();

                // Extraer razon social desde attributes
                String razonSocial = null;
                Map<String, Object> attributes = (Map<String, Object>) user.get("attributes");
                if (attributes != null && attributes.get("razonSocial") != null) {
                    List<String> rsList = (List<String>) attributes.get("razonSocial");
                    if (!rsList.isEmpty()) {
                        razonSocial = rsList.get(0);
                    }
                }

                UsuarioResponseDTO dto = new UsuarioResponseDTO(
                        userId,
                        (String) user.get("username"),
                        (String) user.get("email"),
                        razonSocial,
                        roles
                );
                response.add(dto);
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.emptyList());
        }
    }

    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosPorRol(String rolBuscado) {
        log.debug("Iniciando búsqueda de usuarios con el rol: {}", rolBuscado);

        try {
            ResponseEntity<List<UsuarioResponseDTO>> all = listarUsuarios();

            if (!all.getStatusCode().is2xxSuccessful() || all.getBody() == null) {
                log.error("Error al listar usuarios. Código de estado: {}. Cuerpo nulo: {}",
                        all.getStatusCode(), (all.getBody() == null));
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.emptyList());
            }

            List<UsuarioResponseDTO> filtrados = all.getBody().stream()
                    .filter(u -> u.getRoles().contains(rolBuscado))
                    .collect(Collectors.toList());

            log.info("Usuarios encontrados con el rol '{}': {}", rolBuscado, filtrados.size());

            return ResponseEntity.ok(filtrados);

        } catch (Exception e) {
            log.error("Error inesperado al listar usuarios por rol {}: {}", rolBuscado, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.emptyList());
        }
    }


}
