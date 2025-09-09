package org.paper.controllers;

import org.paper.DTO.UsuarioDAO;
import org.paper.services.UsuarioService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    private final UsuarioService usuarioService;

    public UsuarioController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
    }

    @PostMapping("/crear")
    public ResponseEntity<String> crearUsuario(@RequestBody UsuarioDAO usuario) {
        return usuarioService.crearUsuario(usuario);
    }

    @DeleteMapping("/eliminar/{username}")
    public ResponseEntity<String> eliminarUsuario(@PathVariable String username) {
        return usuarioService.eliminarUsuario(username);
    }

}