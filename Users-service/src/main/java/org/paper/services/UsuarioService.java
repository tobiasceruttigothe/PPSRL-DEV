package org.paper.services;

import lombok.extern.slf4j.Slf4j;
import org.paper.clients.KeycloakClient;
import org.paper.dto.UsuarioCreateDTO;
import org.paper.dto.UsuarioResponseDTO;
import org.paper.entity.Usuario;
import org.paper.exception.KeycloakException;
import org.paper.exception.UsuarioNotFoundException;
import org.paper.exception.UsuarioYaExisteException;
import org.paper.exception.ValidationException;
import org.paper.repository.UsuarioRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
public class UsuarioService {

    private final KeycloakAdminService keycloakAdminService;
    private final UsuarioRepository usuarioRepository;
    private final KeycloakClient keycloakClient;
    private final EmailVerificationService emailVerificationService;

    public UsuarioService(KeycloakAdminService keycloakAdminService,
                          UsuarioRepository usuarioRepository,
                          KeycloakClient keycloakClient,
                          EmailVerificationService emailVerificationService) {
        this.keycloakAdminService = keycloakAdminService;
        this.usuarioRepository = usuarioRepository;
        this.keycloakClient = keycloakClient;
        this.emailVerificationService = emailVerificationService;
    }

    @Transactional
    public ResponseEntity<String> crearUsuario(UsuarioCreateDTO usuario) {
        log.info("Iniciando creación de usuario: {}", usuario.getUsername());
        String token = keycloakAdminService.getAdminToken();

        if (keycloakClient.obtenerUserId(usuario.getUsername(), token) != null) {
            throw new UsuarioYaExisteException(usuario.getUsername());
        }

        keycloakClient.crearUsuario(usuario, token);
        String userId = keycloakClient.obtenerUserId(usuario.getUsername(), token);
        if (userId == null) {
            throw new KeycloakException("obtener UUID", "No se pudo obtener el identificador del usuario creado");
        }
        log.info("Usuario creado en Keycloak con ID: {}", userId);

        keycloakClient.asignarPassword(userId, usuario.getPassword(), token);

        Usuario entity = new Usuario(UUID.fromString(userId));
        usuarioRepository.save(entity);
        log.info("Usuario {} creado con estado PENDING.", usuario.getUsername());

        return ResponseEntity.ok("Usuario creado correctamente. La configuración se completará en unos momentos.");
    }

    @Transactional
    public ResponseEntity<String> eliminarUsuario(String username) {
        log.info("Iniciando proceso de eliminación para usuario: {}", username);
        String token = keycloakAdminService.getAdminToken();
        String userId = keycloakClient.obtenerUserId(username, token);

        if (userId == null) {
            throw new UsuarioNotFoundException(username);
        }

        Optional<Usuario> backup = usuarioRepository.findById(UUID.fromString(userId));
        usuarioRepository.deleteById(UUID.fromString(userId));

        try {
            keycloakClient.eliminarUsuario(userId, token);
        } catch (Exception e) {
            log.error("Error eliminando en Keycloak. Restaurando backup en DB.", e);
            backup.ifPresent(usuarioRepository::save);
            throw e;
        }

        return ResponseEntity.ok("Usuario eliminado correctamente");
    }

    public void cambiarRolUsuarioConToken(String userId, String nuevoRol) {
        String token = keycloakAdminService.getAdminToken();
        cambiarRolUsuario(userId, nuevoRol, token);
    }

    public void cambiarRolUsuario(String userId, String nuevoRol, String token) {
        log.debug("Cambiando rol para usuario {}: {}", userId, nuevoRol);
        List<Map<String, Object>> rolesActuales = keycloakClient.listarRolesDeUsuario(userId, token);

        if (rolesActuales != null && !rolesActuales.isEmpty()) {
            keycloakClient.eliminarRolesDeUsuario(userId, rolesActuales, token);
        }

        Map<String, Object> rol = keycloakClient.obtenerRolPorNombre(nuevoRol, token);
        if (rol == null) {
            throw new ValidationException("rol", "El rol '" + nuevoRol + "' no existe");
        }

        keycloakClient.agregarRolesAUsuario(userId, List.of(rol), token);
        log.info("Rol {} asignado correctamente al usuario {}", nuevoRol, userId);
    }

    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuarios() {
        String token = keycloakAdminService.getAdminToken();
        List<Map<String, Object>> users = keycloakClient.listarUsuarios(token);

        if (users == null) {
            return ResponseEntity.ok(new ArrayList<>());
        }

        List<UsuarioResponseDTO> response = users.stream().map(user -> {
            String userId = (String) user.get("id");
            List<Map<String, Object>> rolesMap = keycloakClient.listarRolesDeUsuario(userId, token);
            List<String> roles = rolesMap.stream().map(role -> (String) role.get("name")).collect(Collectors.toList());

            String razonSocial = "";
            Map<String, Object> attributes = (Map<String, Object>) user.get("attributes");
            if (attributes != null && attributes.get("razonSocial") instanceof List) {
                List<String> rsList = (List<String>) attributes.get("razonSocial");
                if (!rsList.isEmpty()) {
                    razonSocial = rsList.get(0);
                }
            }

            return new UsuarioResponseDTO(
                userId,
                (String) user.get("username"),
                (String) user.get("email"),
                razonSocial,
                roles
            );
        }).collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }

    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosPorRol(String rolBuscado) {
        ResponseEntity<List<UsuarioResponseDTO>> allUsersResponse = listarUsuarios();
        if (!allUsersResponse.getStatusCode().is2xxSuccessful() || allUsersResponse.getBody() == null) {
            throw new KeycloakException("listar usuarios por rol", "No se pudo obtener la lista de usuarios");
        }

        List<UsuarioResponseDTO> filtrados = allUsersResponse.getBody().stream()
                .filter(u -> u.getRoles() != null && u.getRoles().contains(rolBuscado))
                .collect(Collectors.toList());

        return ResponseEntity.ok(filtrados);
    }
}