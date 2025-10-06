package org.paper.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.paper.dto.UsuarioCreateDTO;
import org.paper.dto.UsuarioResponseDTO;
import org.paper.repository.UsuarioRepository;
import org.paper.services.UsuarioActivacionService;
import org.paper.services.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UsuarioController.class)
class UsuarioControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UsuarioService usuarioService;

    @MockBean
    private UsuarioRepository usuarioRepository;

    @MockBean
    private UsuarioActivacionService usuarioActivacionService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testCrearUsuario() throws Exception {
        UsuarioCreateDTO dto = new UsuarioCreateDTO();
        dto.setUsername("testUser");
        dto.setEmail("test@example.com");
        dto.setRazonSocial("MiEmpresa");
        dto.setPassword("Password123");
        dto.setEnabled(true);
        dto.setEmailVerified(false);

        when(usuarioService.crearUsuario(any(UsuarioCreateDTO.class)))
                .thenReturn(ResponseEntity.ok("Usuario creado correctamente"));

        mockMvc.perform(post("/api/usuarios/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(content().string("Usuario creado correctamente"));
    }

    @Test
    void testAsignarRolAdmin() throws Exception {
        mockMvc.perform(put("/api/usuarios/123/rol/admin"))
                .andExpect(status().isOk())
                .andExpect(content().string("Rol cambiado a ADMIN"));

        Mockito.verify(usuarioService).cambiarRolUsuarioConToken("123", "ADMIN");
    }

    @Test
    void testAsignarRolCliente() throws Exception {
        mockMvc.perform(put("/api/usuarios/123/rol/cliente"))
                .andExpect(status().isOk())
                .andExpect(content().string("Rol cambiado a CLIENTE"));

        Mockito.verify(usuarioService).cambiarRolUsuarioConToken("123", "CLIENTE");
    }

    @Test
    void testEliminarUsuario() throws Exception {
        when(usuarioService.eliminarUsuario("testUser"))
                .thenReturn(ResponseEntity.ok("Usuario eliminado correctamente"));

        mockMvc.perform(delete("/api/usuarios/eliminate/testUser"))
                .andExpect(status().isOk())
                .andExpect(content().string("Usuario eliminado correctamente"));
    }

    @Test
    void testListarUsuarios() throws Exception {
        UsuarioResponseDTO user = new UsuarioResponseDTO(
                UUID.randomUUID().toString(),
                "testUser",
                "test@example.com",
                "Razon Social",
                List.of("CLIENTE")
        );

        when(usuarioService.listarUsuarios())
                .thenReturn(ResponseEntity.ok(List.of(user)));

        mockMvc.perform(get("/api/usuarios/list/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("testUser"))
                .andExpect(jsonPath("$[0].roles[0]").value("CLIENTE"));
    }

    @Test
    void testListarUsuariosClientes() throws Exception {
        when(usuarioService.listarUsuariosPorRol("CLIENTE"))
                .thenReturn(ResponseEntity.ok(List.of()));

        mockMvc.perform(get("/api/usuarios/list/users/clients"))
                .andExpect(status().isOk());
    }

    @Test
    void testListarUsuariosAdmins() throws Exception {
        when(usuarioService.listarUsuariosPorRol("ADMIN"))
                .thenReturn(ResponseEntity.ok(List.of()));

        mockMvc.perform(get("/api/usuarios/list/users/admins"))
                .andExpect(status().isOk());
    }

    @Test
    void testListarUsuariosInteresados() throws Exception {
        when(usuarioService.listarUsuariosPorRol("INTERESADO"))
                .thenReturn(ResponseEntity.ok(List.of()));

        mockMvc.perform(get("/api/usuarios/list/users/interested"))
                .andExpect(status().isOk());
    }
}