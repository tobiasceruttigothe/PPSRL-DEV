package org.paper.controllers;

import jakarta.validation.Valid;
import org.paper.dto.UsuarioCreateDTO;
import org.paper.dto.UsuarioResponseDTO;
import org.paper.services.UsuarioService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    private final UsuarioService usuarioService;

    public UsuarioController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
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
}