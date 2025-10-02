package org.paper.controllers;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
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
public class UsuarioController {

    private final UsuarioService usuarioService;
    private final UsuarioRepository usuarioRepository;
    private final UsuarioActivacionService usuarioActivacionService;

    public UsuarioController(UsuarioService usuarioService, UsuarioRepository usuarioRepository, UsuarioActivacionService usuarioActivacionService) {
        this.usuarioService = usuarioService;
        this.usuarioRepository = usuarioRepository;
        this.usuarioActivacionService = usuarioActivacionService;
    }

//eliminar
    @GetMapping("/obtener/{username}")
    public ResponseEntity<?> obtenerUsuarioPorId(@PathVariable String username) {
        return ResponseEntity.ok(usuarioService.prueba(username));
    }


    @PostMapping("/create")
    public ResponseEntity<?> crearUsuario(@Valid @RequestBody UsuarioCreateDTO usuarioDTO) {
        return usuarioService.crearUsuario(usuarioDTO);
    }
//revisar, cambiar por username
    @PutMapping("/{userId}/rol/admin")
    public ResponseEntity<String> asignarRolAdmin(@PathVariable String userId) {
        usuarioService.cambiarRolUsuarioConToken(userId, "ADMIN");
        return ResponseEntity.ok("Rol cambiado a ADMIN");
    }
//revisar, cambiar por username
    @PutMapping("/{userId}/rol/cliente")
    public ResponseEntity<String> asignarRolCliente(@PathVariable String userId) {
        usuarioService.cambiarRolUsuarioConToken(userId, "CLIENTE");
        return ResponseEntity.ok("Rol cambiado a CLIENTE");
    }

    @DeleteMapping("/eliminate/{username}")
    public ResponseEntity<String> eliminarUsuario(@PathVariable String username) {
        return usuarioService.eliminarUsuario(username);
    }

    @GetMapping("/list/users")
    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuarios() {
        return usuarioService.listarUsuarios(); // Todos
    }

    @GetMapping("/list/users/interested")
    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosInteresados() {
        return usuarioService.listarUsuariosPorRol("INTERESADO");
    }

    @GetMapping("/list/users/clients")
    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosClientes() {
        return usuarioService.listarUsuariosPorRol("CLIENTE");
    }

    @GetMapping("/list/users/admins")
    public ResponseEntity<List<UsuarioResponseDTO>> listarUsuariosAdmins() {
        return usuarioService.listarUsuariosPorRol("ADMIN");
    }





    /**
     * Listar usuarios fallidos (solo admin)
     */
    @GetMapping("/failed")
    public ResponseEntity<List<Usuario>> listarUsuariosFallidos() {
        log.info("Listando usuarios fallidos");
        List<Usuario> fallidos = usuarioRepository.findByStatusOrderByFechaRegistroDesc(UsuarioStatus.FAILED);
        return ResponseEntity.ok(fallidos);
    }

    /**
     * Listar usuarios pendientes (solo admin)
     */
    @GetMapping("/pending")
    public ResponseEntity<List<Usuario>> listarUsuariosPendientes() {
        log.info("Listando usuarios pendientes");
        List<Usuario> pendientes = usuarioRepository.findByStatus(UsuarioStatus.PENDING);
        return ResponseEntity.ok(pendientes);
    }

    /**
     * Reintentar activación de usuario fallido manualmente
     */
    @PostMapping("/retry/{userId}")
    public ResponseEntity<String> reintentarUsuario(@PathVariable String userId) {
        log.info("Reintento manual solicitado para usuario: {}", userId);
        usuarioActivacionService.reintentarUsuarioFallido(userId);
        return ResponseEntity.ok("Usuario enviado a reprocesamiento");
    }


}