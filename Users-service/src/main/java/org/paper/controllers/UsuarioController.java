package org.paper.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.paper.dto.ErrorResponse;
import org.paper.dto.UsuarioCreateDTO;
import org.paper.dto.UsuarioResponseDTO;
import org.paper.entity.Usuario;
import org.paper.entity.UsuarioStatus;
import org.paper.repository.UsuarioRepository;
import org.paper.services.UsuarioActivacionService;
import org.paper.services.UsuarioService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/usuarios")
@Tag(name = "Usuarios", description = "Gestión de usuarios del sistema")
public class UsuarioController {

    private final UsuarioService usuarioService;
    private final UsuarioRepository usuarioRepository;
    private final UsuarioActivacionService usuarioActivacionService;

    public UsuarioController(UsuarioService usuarioService,
                             UsuarioRepository usuarioRepository,
                             UsuarioActivacionService usuarioActivacionService) {
        this.usuarioService = usuarioService;
        this.usuarioRepository = usuarioRepository;
        this.usuarioActivacionService = usuarioActivacionService;
    }

    @PostMapping("/create")
    @Operation(
            summary = "Crear nuevo usuario",
            description = """
            Crea un nuevo usuario en el sistema. El usuario será creado con rol INTERESADO 
            y recibirá un email de verificación. El proceso de activación completo puede 
            tomar hasta 1 minuto.
            
            **Flujo:**
            1. Usuario se registra
            2. Se crea en Keycloak y BD (estado PENDING)
            3. Job en background asigna rol y envía email
            4. Usuario verifica email
            5. Estado cambia a ACTIVE
            """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Usuario creado correctamente",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Datos de entrada inválidos (validación falló)",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "El usuario ya existe en el sistema",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))
            ),
            @ApiResponse(
                    responseCode = "502",
                    description = "Error de comunicación con Keycloak",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))
            )
    })
    public ResponseEntity<?> crearUsuario(
            @Valid @RequestBody
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Datos del nuevo usuario. Todos los campos son obligatorios.",
                    required = true
            )
            UsuarioCreateDTO usuarioDTO) {
        return usuarioService.crearUsuario(usuarioDTO);
    }

    @PutMapping("/{userId}/rol/admin")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Asignar rol de administrador",
            description = """
            Cambia el rol de un usuario a ADMIN. 
            
            **Requiere:** Rol ADMIN
            
            ⚠️ **Nota:** El userId es el UUID de Keycloak, no el username.
            """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Rol cambiado correctamente"),
            @ApiResponse(responseCode = "401", description = "No autenticado (token inválido o expirado)"),
            @ApiResponse(responseCode = "403", description = "Sin permisos (rol insuficiente)"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    public ResponseEntity<String> asignarRolAdmin(
            @Parameter(
                    description = "ID del usuario (UUID de Keycloak)",
                    required = true,
                    example = "550e8400-e29b-41d4-a716-446655440000"
            )
            @PathVariable String userId) {
        usuarioService.cambiarRolUsuarioConToken(userId, "ADMIN");
        return ResponseEntity.ok("Rol cambiado a ADMIN");
    }

    @PutMapping("/{userId}/rol/cliente")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Asignar rol de cliente",
            description = """
            Cambia el rol de un usuario a CLIENTE.
            
            **Requiere:** Rol ADMIN
            
            ⚠️ **Nota:** El userId es el UUID de Keycloak, no el username.
            """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Rol cambiado correctamente"),
            @ApiResponse(responseCode = "401", description = "No autenticado"),
            @ApiResponse(responseCode = "403", description = "Sin permisos"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    public ResponseEntity<String> asignarRolCliente(
            @Parameter(
                    description = "ID del usuario (UUID de Keycloak)",
                    required = true,
                    example = "550e8400-e29b-41d4-a716-446655440000"
            )
            @PathVariable String userId) {
        usuarioService.cambiarRolUsuarioConToken(userId, "CLIENTE");
        return ResponseEntity.ok("Rol cambiado a CLIENTE");
    }

    @DeleteMapping("/eliminate/{username}")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Eliminar usuario",
            description = """
            Elimina un usuario del sistema (tanto de Keycloak como de la base de datos).
            
            **Requiere:** Rol ADMIN
            
            ⚠️ **Precaución:** Esta acción es irreversible.
            """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Usuario eliminado correctamente"),
            @ApiResponse(responseCode = "401", description = "No autenticado"),
            @ApiResponse(responseCode = "403", description = "Sin permisos"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado"),
            @ApiResponse(responseCode = "500", description = "Error al eliminar (rollback aplicado)")
    })
    public ResponseEntity<String> eliminarUsuario(
            @Parameter(
                    description = "Nombre de usuario (username)",
                    required = true,
                    example = "juan_perez"
            )
            @PathVariable String username) {
        return usuarioService.eliminarUsuario(username);
    }

    @GetMapping("/list/users")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Listar todos los usuarios",
            description = """
            Retorna la lista completa de usuarios del sistema con sus roles y datos básicos.
            
            **Requiere:** Rol ADMIN
            """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Lista de usuarios obtenida correctamente"
            ),
            @ApiResponse(responseCode = "401", description = "No autenticado"),
            @ApiResponse(responseCode = "403", description = "Sin permisos")
    })
    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuarios() {
        return usuarioService.listarUsuarios();
    }

    @GetMapping("/list/users/interested")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Listar usuarios interesados",
            description = """
            Retorna usuarios con rol INTERESADO (usuarios recién registrados).
            
            **Requiere:** Rol ADMIN
            """
    )
    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosInteresados() {
        return usuarioService.listarUsuariosPorRol("INTERESADO");
    }

    @GetMapping("/list/users/clients")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Listar usuarios clientes",
            description = """
            Retorna usuarios con rol CLIENTE (usuarios activos del sistema).
            
            **Requiere:** Rol ADMIN
            """
    )
    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosClientes() {
        return usuarioService.listarUsuariosPorRol("CLIENTE");
    }

    @GetMapping("/list/users/admins")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Listar administradores",
            description = """
            Retorna usuarios con rol ADMIN.
            
            **Requiere:** Rol ADMIN
            """
    )
    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosAdmins() {
        return usuarioService.listarUsuariosPorRol("ADMIN");
    }

    @GetMapping("/failed")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Listar usuarios fallidos",
            description = """
            Retorna usuarios que fallaron durante el proceso de activación automática 
            y requieren revisión manual.
            
            **Requiere:** Rol ADMIN
            
            Estos usuarios pueden ser reintentados manualmente usando el endpoint /retry/{userId}
            """
    )
    public ResponseEntity<List<Usuario>> listarUsuariosFallidos() {
        log.info("Listando usuarios fallidos");
        List<Usuario> fallidos = usuarioRepository.findByStatusOrderByFechaRegistroDesc(UsuarioStatus.FAILED);
        return ResponseEntity.ok(fallidos);
    }

    @GetMapping("/pending")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Listar usuarios pendientes",
            description = """
            Retorna usuarios en proceso de activación (estado PENDING).
            
            **Requiere:** Rol ADMIN
            
            El job en background procesa estos usuarios automáticamente cada 1 minuto.
            """
    )
    public ResponseEntity<List<Usuario>> listarUsuariosPendientes() {
        log.info("Listando usuarios pendientes");
        List<Usuario> pendientes = usuarioRepository.findByStatus(UsuarioStatus.PENDING);
        return ResponseEntity.ok(pendientes);
    }

    @PostMapping("/retry/{userId}")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Reintentar activación de usuario",
            description = """
            Reintenta manualmente la activación de un usuario que falló (estado FAILED).
            
            **Requiere:** Rol ADMIN
            
            El usuario volverá a estado PENDING y será procesado inmediatamente.
            """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Usuario enviado a reprocesamiento"),
            @ApiResponse(responseCode = "400", description = "El usuario no está en estado FAILED"),
            @ApiResponse(responseCode = "401", description = "No autenticado"),
            @ApiResponse(responseCode = "403", description = "Sin permisos"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    public ResponseEntity<String> reintentarUsuario(
            @Parameter(
                    description = "ID del usuario (UUID)",
                    required = true,
                    example = "550e8400-e29b-41d4-a716-446655440000"
            )
            @PathVariable String userId) {
        log.info("Reintento manual solicitado para usuario: {}", userId);
        usuarioActivacionService.reintentarUsuarioFallido(userId);
        return ResponseEntity.ok("Usuario enviado a reprocesamiento");
    }
}