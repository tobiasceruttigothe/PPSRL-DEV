package org.paper.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.paper.clients.KeycloakClient;
import org.paper.dto.UsuarioCreateDTO;
import org.paper.entity.Usuario;
import org.paper.exception.KeycloakException;
import org.paper.exception.UsuarioYaExisteException;
import org.paper.repository.UsuarioRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UsuarioServiceTest {

    @Mock private KeycloakAdminService keycloakAdminService;
    @Mock private UsuarioRepository usuarioRepository;
    @Mock private KeycloakClient keycloakClient;
    @Mock private EmailVerificationService emailVerificationService;

    @InjectMocks private UsuarioService usuarioService;

    @BeforeEach
    void setUp() {
        lenient().when(keycloakAdminService.getAdminToken()).thenReturn("fake-admin-token");
    }

    @Test
    void testCrearUsuario_ok() {
        // Arrange
        UsuarioCreateDTO dto = new UsuarioCreateDTO("testUser", "test@example.com", "password123", "MiEmpresa", true, false);
        String newUserId = UUID.randomUUID().toString();

        when(keycloakClient.obtenerUserId(eq("testUser"), anyString()))
            .thenReturn(null) // First call: user doesn't exist
            .thenReturn(newUserId); // Second call: user exists after creation

        doNothing().when(keycloakClient).crearUsuario(any(UsuarioCreateDTO.class), anyString());
        doNothing().when(keycloakClient).asignarPassword(eq(newUserId), eq(dto.getPassword()), anyString());
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(i -> i.getArgument(0));

        // Act
        ResponseEntity<String> response = usuarioService.crearUsuario(dto);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("Usuario creado correctamente"));
        verify(usuarioRepository).save(any(Usuario.class));
    }

    @Test
    void testCrearUsuario_fallaPorUsuarioYaExistente() {
        // Arrange
        UsuarioCreateDTO dto = new UsuarioCreateDTO("testUser", "test@example.com", "password123", "MiEmpresa", true, false);
        when(keycloakClient.obtenerUserId(eq("testUser"), anyString())).thenReturn("existing-id");

        // Act & Assert
        assertThrows(UsuarioYaExisteException.class, () -> usuarioService.crearUsuario(dto));
        verify(keycloakClient, never()).crearUsuario(any(), any());
    }

    @Test
    void testCrearUsuario_fallaKeycloakAlCrear() {
        // Arrange
        UsuarioCreateDTO dto = new UsuarioCreateDTO("badUser", "bad@example.com", "password123", "MiEmpresa", true, false);
        when(keycloakClient.obtenerUserId(eq("badUser"), anyString())).thenReturn(null);
        doThrow(new KeycloakException("crear usuario", 500, "Error"))
            .when(keycloakClient).crearUsuario(any(UsuarioCreateDTO.class), anyString());

        // Act & Assert
        assertThrows(KeycloakException.class, () -> usuarioService.crearUsuario(dto));
        verify(usuarioRepository, never()).save(any());
    }

    @Test
    void testEliminarUsuario_ok() {
        // Arrange
        String username = "testUser";
        String userId = UUID.randomUUID().toString();

        when(keycloakClient.obtenerUserId(eq(username), anyString())).thenReturn(userId);
        when(usuarioRepository.findById(UUID.fromString(userId))).thenReturn(Optional.of(new Usuario(UUID.fromString(userId))));
        doNothing().when(keycloakClient).eliminarUsuario(eq(userId), anyString());

        // Act
        ResponseEntity<String> response = usuarioService.eliminarUsuario(username);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Usuario eliminado correctamente", response.getBody());
        verify(usuarioRepository).deleteById(UUID.fromString(userId));
    }
}