package org.paper.controllers;

import jakarta.validation.Valid;
import org.paper.DTO.UsuarioCreateDTO;
import org.paper.DTO.UsuarioResponseDTO;
import org.paper.services.UsuarioService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    private final UsuarioService usuarioService;

    public UsuarioController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
    }

    @PostMapping("/create")
    public ResponseEntity<?> crearUsuario(@Valid @RequestBody UsuarioCreateDTO usuarioDTO) {
        return usuarioService.crearUsuario(usuarioDTO);
    }

    @PutMapping("/{userId}/rol/admin")
    public ResponseEntity<String> asignarRolAdmin(@PathVariable String userId) {
        usuarioService.cambiarRolUsuarioConToken(userId, "ADMIN");
        return ResponseEntity.ok("Rol cambiado a ADMIN");
    }

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