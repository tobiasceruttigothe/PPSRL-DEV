package org.paper.services;

import lombok.extern.slf4j.Slf4j;
import org.paper.dto.UsuarioCreateDTO;
import org.paper.dto.UsuarioResponseDTO;
import org.paper.entity.Usuario;
import org.paper.exception.*;
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
    private final EmailVerificationService emailVerificationService;

    public UsuarioService(KeycloakAdminService keycloakAdminService,
                          UsuarioRepository usuarioRepository,
                          WebClient webClient, EmailVerificationService emailVerificationService) {
        this.keycloakAdminService = keycloakAdminService;
        this.usuarioRepository = usuarioRepository;
        this.webClient = webClient;
        this.emailVerificationService = emailVerificationService;
    }

    @Transactional
    public ResponseEntity<String> crearUsuario(UsuarioCreateDTO usuario) {
        log.info("Iniciando creación de usuario: {}", usuario.getUsername());

        String token;
        try {
            token = keycloakAdminService.getAdminToken();
        } catch (Exception e) {
            log.error("Error al obtener token de administrador", e);
            throw new KeycloakException("obtener token", "No se pudo autenticar con Keycloak", e);
        }

        String userId = null;
        boolean usuarioExisteEnKeycloak = false;

        try {
            // 1. Verificar si el usuario ya existe en Keycloak
            log.debug("Verificando si el usuario {} ya existe", usuario.getUsername());
            try {
                String existingUserId = obtenerUserId(usuario.getUsername(), token);
                if (existingUserId != null) {
                    log.warn("El usuario {} ya existe en Keycloak", usuario.getUsername());
                    throw new UsuarioYaExisteException(usuario.getUsername());
                }
            } catch (WebClientResponseException.NotFound e) {
                // Usuario no existe, podemos continuar
                log.debug("Usuario {} no existe, procediendo con la creación", usuario.getUsername());
            }

            // 2. Crear usuario en Keycloak
            log.debug("Creando usuario en Keycloak");
            String jsonBody = String.format(
                    "{ \"username\":\"%s\", \"enabled\":%b, \"email\":\"%s\", \"emailVerified\":%b, \"attributes\": { \"razonSocial\": [\"%s\"] } }",
                    usuario.getUsername(),
                    usuario.isEnabled(),
                    usuario.getEmail(),
                    usuario.isEmailVerified(),
                    usuario.getRazonSocial()
            );

            ResponseEntity<String> response;
            try {
                response = webClient.post()
                        .uri("/admin/realms/tesina/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(jsonBody)
                        .retrieve()
                        .toEntity(String.class)
                        .block();
            } catch (WebClientResponseException.Conflict e) {
                log.error("Conflicto al crear usuario en Keycloak: {}", e.getResponseBodyAsString());
                throw new UsuarioYaExisteException(usuario.getUsername());
            } catch (WebClientResponseException e) {
                log.error("Error HTTP {} al crear usuario en Keycloak: {}",
                        e.getStatusCode(), e.getResponseBodyAsString());
                throw new KeycloakException(
                        "crear usuario",
                        e.getStatusCode().value(),
                        e.getResponseBodyAsString()
                );
            }

            if (response == null || !response.getStatusCode().is2xxSuccessful()) {
                log.error("Respuesta inválida de Keycloak al crear usuario: {}", response);
                throw new KeycloakException(
                        "crear usuario",
                        "Respuesta inválida del servidor"
                );
            }

            // 3. Obtener UUID
            log.debug("Obteniendo UUID del usuario");
            userId = obtenerUserId(usuario.getUsername(), token);
            if (userId == null) {
                log.error("No se pudo obtener el UUID de Keycloak para: {}", usuario.getUsername());
                throw new KeycloakException(
                        "obtener UUID",
                        "No se pudo obtener el identificador del usuario creado"
                );
            }

            usuarioExisteEnKeycloak = true;
            log.info("Usuario creado en Keycloak con ID: {}", userId);

            // 4. Asignar password
            if (usuario.getPassword() != null && !usuario.getPassword().isEmpty()) {
                log.debug("Asignando contraseña");
                asignarPassword(usuario, token, userId);
            }

            // 5. Guardar en Postgres (protegido por @Transactional)
            log.debug("Guardando usuario en base de datos");
            Usuario entity = new Usuario();
            entity.setId(UUID.fromString(userId));
            entity.setFechaRegistro(LocalDateTime.now());
            usuarioRepository.save(entity);

            // 6. Asignar rol por defecto (INTERESADO)
            log.debug("Asignando rol INTERESADO");
            cambiarRolUsuario(userId, "INTERESADO", token);

            // 7. Enviar email de verificación
            log.debug("Enviando email de verificación");
            try {
                emailVerificationService.createAndSendVerification(userId, usuario.getUsername(), usuario.getEmail());
            } catch (Exception e) {
                // Email no es crítico
                log.warn("No se pudo enviar email de verificación a {}: {}",
                        usuario.getEmail(), e.getMessage());
            }

            log.info("Usuario {} creado correctamente", usuario.getUsername());
            return ResponseEntity.ok("Usuario creado correctamente. Se envió mail de verificación.");

        } catch (UsuarioYaExisteException | KeycloakException | ValidationException e) {
            log.error("Error conocido durante la creación del usuario {}: {}",
                    usuario.getUsername(), e.getMessage());

            // Intentar rollback si el usuario fue creado en Keycloak
            if (usuarioExisteEnKeycloak && userId != null) {
                intentarRollbackKeycloak(userId, token);
            }
            throw e;

        } catch (Exception e) {
            log.error("Error inesperado durante la creación del usuario {}: {}",
                    usuario.getUsername(), e.getMessage(), e);

            // Intentar rollback si el usuario fue creado en Keycloak
            if (usuarioExisteEnKeycloak && userId != null) {
                intentarRollbackKeycloak(userId, token);
            }

            throw new KeycloakException(
                    "crear usuario",
                    "Error inesperado durante la creación: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Intenta hacer rollback eliminando el usuario de Keycloak
     */
    private void intentarRollbackKeycloak(String userId, String token) {
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
/*
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
            log.error("Error al enviar email. Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new EmailException(
                    userId,
                    "Error al enviar email de verificación desde Keycloak",
                    e
            );
        }
    }

 */
/*
    public void verificarEmailUsuario(String userId) {
        String token = keycloakAdminService.getAdminToken();
        String jsonBody = "{ \"emailVerified\": true }";

        try {
            webClient.put()
                    .uri("/admin/realms/tesina/users/{id}", userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(jsonBody)
                    .retrieve()
                    .toBodilessEntity()
                    .block();

            log.info("Email verificado para usuario: {}", userId);
        } catch (WebClientResponseException e) {
            log.error("Error al verificar email del usuario {}: {}", userId, e.getMessage());
            throw new KeycloakException(
                    "verificar email",
                    e.getStatusCode().value(),
                    e.getResponseBodyAsString()
            );
        }
    }

 */

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
        } catch (WebClientResponseException e) {
            log.error("Error al asignar password: {}", e.getMessage(), e);
            throw new KeycloakException(
                    "asignar password",
                    e.getStatusCode().value(),
                    "No se pudo asignar la contraseña"
            );
        }
    }

    public void eliminarUsuarioEnKeycloak(String userId, String token) {
        try {
            webClient.delete()
                    .uri("/admin/realms/tesina/users/{id}", userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
            log.info("Usuario {} eliminado de Keycloak", userId);
        } catch (WebClientResponseException e) {
            log.error("Error al eliminar usuario {} de Keycloak: {}", userId, e.getMessage());
            throw new KeycloakException(
                    "eliminar usuario",
                    e.getStatusCode().value(),
                    "No se pudo eliminar el usuario de Keycloak"
            );
        }
    }

    public String prueba(String username) {
        String token = keycloakAdminService.getAdminToken();
        return obtenerUserId(username, token);
    }

    public String obtenerUserId(String username, String token) {
        try {
            List<Map<String, Object>> body = webClient.get()
                    .uri("/admin/realms/tesina/users?username={username}", username)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .collectList()
                    .block();

            if (body == null || body.isEmpty()) {
                return null;
            }

            if (body.size() > 1) {
                log.warn("Más de un usuario encontrado con username: {}", username);
                throw new ValidationException(
                        "username",
                        "Múltiples usuarios encontrados con el mismo nombre"
                );
            }

            return (String) body.get(0).get("id");

        } catch (WebClientResponseException e) {
            log.error("Error al obtener userId para {}: {}", username, e.getMessage());
            throw new KeycloakException(
                    "obtener usuario",
                    e.getStatusCode().value(),
                    "No se pudo buscar el usuario en Keycloak"
            );
        }
    }

    @Transactional
    public ResponseEntity<String> eliminarUsuario(String username) {
        log.info("Iniciando proceso de eliminación para usuario: {}", username);

        String token;
        try {
            token = keycloakAdminService.getAdminToken();
        } catch (Exception e) {
            throw new KeycloakException("obtener token", "No se pudo autenticar", e);
        }

        try {
            String userId = obtenerUserId(username, token);
            if (userId == null) {
                log.warn("Usuario no encontrado en Keycloak: {}", username);
                throw new UsuarioNotFoundException(username);
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
            } catch (KeycloakException e) {
                log.error("Error eliminando usuario {} en Keycloak. Restaurando backup en Postgres.", username);
                backup.ifPresent(usuario -> {
                    usuarioRepository.save(usuario);
                    log.warn("Usuario {} restaurado en Postgres tras fallo en Keycloak", username);
                });
                throw e; // Re-lanzar para que GlobalExceptionHandler lo maneje
            }

            log.info("Proceso de eliminación completado para usuario: {}", username);
            return ResponseEntity.ok("Usuario eliminado correctamente");

        } catch (UsuarioNotFoundException | KeycloakException e) {
            // Re-lanzar excepciones conocidas
            throw e;
        } catch (Exception e) {
            log.error("Error inesperado al eliminar usuario {}. Detalle: {}", username, e.getMessage(), e);
            throw new KeycloakException(
                    "eliminar usuario",
                    "Error inesperado: " + e.getMessage(),
                    e
            );
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
                throw new ValidationException("rol", "El rol '" + nuevoRol + "' no existe");
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

        } catch (WebClientResponseException e) {
            log.error("Error al cambiar rol del usuario {}: {} - {}",
                    userId, e.getStatusCode(), e.getResponseBodyAsString());
            throw new KeycloakException(
                    "cambiar rol",
                    e.getStatusCode().value(),
                    "No se pudo cambiar el rol del usuario"
            );
        } catch (ValidationException e) {
            throw e; // Re-lanzar tal cual
        } catch (Exception e) {
            log.error("Error inesperado al cambiar rol del usuario {}: {}", userId, e.getMessage(), e);
            throw new KeycloakException(
                    "cambiar rol",
                    "Error inesperado al cambiar rol: " + e.getMessage(),
                    e
            );
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
                log.error("Respuesta null al listar usuarios");
                throw new KeycloakException("listar usuarios", "Respuesta vacía de Keycloak");
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

        } catch (WebClientResponseException e) {
            log.error("Error HTTP al listar usuarios: {} - {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new KeycloakException(
                    "listar usuarios",
                    e.getStatusCode().value(),
                    "No se pudo obtener la lista de usuarios"
            );
        } catch (Exception e) {
            log.error("Error inesperado al listar usuarios: {}", e.getMessage(), e);
            throw new KeycloakException(
                    "listar usuarios",
                    "Error inesperado: " + e.getMessage(),
                    e
            );
        }
    }

    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosPorRol(String rolBuscado) {
        log.debug("Iniciando búsqueda de usuarios con el rol: {}", rolBuscado);

        try {
            ResponseEntity<List<UsuarioResponseDTO>> all = listarUsuarios();

            if (!all.getStatusCode().is2xxSuccessful() || all.getBody() == null) {
                log.error("Error al listar usuarios. Código de estado: {}", all.getStatusCode());
                throw new KeycloakException("listar usuarios por rol", "No se pudo obtener la lista de usuarios");
            }

            List<UsuarioResponseDTO> filtrados = all.getBody().stream()
                    .filter(u -> u.getRoles().contains(rolBuscado))
                    .collect(Collectors.toList());

            log.info("Usuarios encontrados con el rol '{}': {}", rolBuscado, filtrados.size());

            return ResponseEntity.ok(filtrados);

        } catch (KeycloakException e) {
            throw e; // Re-lanzar tal cual
        } catch (Exception e) {
            log.error("Error inesperado al listar usuarios por rol {}: {}", rolBuscado, e.getMessage(), e);
            throw new KeycloakException(
                    "listar usuarios por rol",
                    "Error inesperado: " + e.getMessage(),
                    e
            );
        }
    }
}