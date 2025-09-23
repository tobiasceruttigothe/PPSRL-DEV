package org.paper.controllers;

import org.paper.DTO.UsuarioDTO;
import org.paper.services.UsuarioService;
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

    @PostMapping("/crear")
    public ResponseEntity<String> crearUsuario(@RequestBody UsuarioDTO usuario) {
        return usuarioService.crearUsuario(usuario);
    }

    @DeleteMapping("/eliminar/{username}")
    public ResponseEntity<String> eliminarUsuario(@PathVariable String username) {
        return usuarioService.eliminarUsuario(username);
    }

    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> listarUsuarios() {
        return usuarioService.listarUsuarios();
    }


}