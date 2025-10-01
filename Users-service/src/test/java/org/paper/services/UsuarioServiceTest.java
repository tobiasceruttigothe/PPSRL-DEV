package org.paper.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.paper.DTO.UsuarioCreateDTO;
import org.paper.DTO.UsuarioResponseDTO;
import org.paper.entity.Usuario;
import org.paper.repository.UsuarioRepository;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class UsuarioServiceTest {

    @Mock
    private KeycloakAdminService keycloakAdminService;

    @Mock
    private UsuarioRepository usuarioRepository;

    @Mock
    private WebClient webClient;

    @InjectMocks
    private UsuarioService usuarioService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(keycloakAdminService.getAdminToken()).thenReturn("fake-token");
    }

    // 🔹 Test crear usuario OK
    @Test
    void testCrearUsuario_ok() {
        // DTO de prueba
        UsuarioCreateDTO usuarioDTO = new UsuarioCreateDTO();
        usuarioDTO.setUsername("testUser");
        usuarioDTO.setEmail("test@example.com");
        usuarioDTO.setPassword("password123");
        usuarioDTO.setRazonSocial("MiEmpresa");
        usuarioDTO.setEnabled(true);
        usuarioDTO.setEmailVerified(false);

        // Mock de Keycloak token
        when(keycloakAdminService.getAdminToken()).thenReturn("mock-token");

        // 🔹 Mock POST para crear usuario
        WebClient.RequestBodyUriSpec postRequest = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec postBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec postHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec postResponseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.post()).thenReturn(postRequest);
        when(postRequest.uri(anyString())).thenReturn(postBodySpec);
        when(postBodySpec.header(anyString(), anyString())).thenReturn(postBodySpec);
        when(postBodySpec.contentType(any())).thenReturn(postBodySpec);
        when(postBodySpec.bodyValue(any())).thenReturn(postHeadersSpec);
        when(postHeadersSpec.retrieve()).thenReturn(postResponseSpec);
        when(postResponseSpec.toEntity(String.class))
                .thenReturn(Mono.just(ResponseEntity.ok("Created")));

        // 🔹 Mock GET para obtener UUID
        WebClient.RequestHeadersUriSpec getRequest = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec getHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec getResponseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.get()).thenReturn(getRequest);
        when(getRequest.uri(anyString(), any(Object[].class))).thenReturn(getHeadersSpec);
        when(getHeadersSpec.header(anyString(), anyString())).thenReturn(getHeadersSpec);
        when(getHeadersSpec.retrieve()).thenReturn(getResponseSpec);
        when(getResponseSpec.bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {}))
                .thenReturn(Flux.just(Map.of("id", "123e4567-e89b-12d3-a456-426614174000")));

        // 🔹 Mock PUT para asignar password
        WebClient.RequestBodyUriSpec putRequest = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec putBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec putHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec putResponseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.put()).thenReturn(putRequest);
        when(putRequest.uri(anyString(), any(Object[].class))).thenReturn(putBodySpec);
        when(putBodySpec.header(anyString(), anyString())).thenReturn(putBodySpec);
        when(putBodySpec.contentType(any())).thenReturn(putBodySpec);
        when(putBodySpec.bodyValue(any())).thenReturn(putHeadersSpec);
        when(putHeadersSpec.retrieve()).thenReturn(putResponseSpec);
        when(putResponseSpec.toBodilessEntity()).thenReturn(Mono.just(ResponseEntity.ok().build()));

        // 🔹 Mock DELETE para rollback (opcional)
        WebClient.RequestHeadersUriSpec deleteRequest = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec deleteHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec deleteResponseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.delete()).thenReturn(deleteRequest);
        when(deleteRequest.uri(anyString(), any(Object[].class))).thenReturn(deleteHeadersSpec);
        when(deleteHeadersSpec.header(anyString(), anyString())).thenReturn(deleteHeadersSpec);
        when(deleteHeadersSpec.retrieve()).thenReturn(deleteResponseSpec);
        when(deleteResponseSpec.toBodilessEntity()).thenReturn(Mono.just(ResponseEntity.ok().build()));

        // 🔹 Mock repositorio
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(i -> i.getArgument(0));

        // Ejecutar método
        ResponseEntity<String> response = usuarioService.crearUsuario(usuarioDTO);

        // Verificar resultados
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("Usuario creado correctamente"));

        // Verificar que se llamó a WebClient.put() para asignar password
        verify(webClient, atLeastOnce()).put();
    }

    @Test
    void testCrearUsuario_falla() {
        // DTO con datos "malos"
        UsuarioCreateDTO dto = new UsuarioCreateDTO();
        dto.setUsername("badUser");
        dto.setEmail("bad@example.com");
        dto.setPassword("wrongpassword");

        // Mock token de Keycloak
        when(keycloakAdminService.getAdminToken()).thenReturn("mock-token");

        // 🔹 Mock POST para crear usuario y simular BAD_REQUEST
        WebClient.RequestBodyUriSpec postRequest = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec postBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec postHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec postResponseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.post()).thenReturn(postRequest);
        when(postRequest.uri(anyString())).thenReturn(postBodySpec);
        when(postBodySpec.header(anyString(), anyString())).thenReturn(postBodySpec);
        when(postBodySpec.contentType(any())).thenReturn(postBodySpec);
        when(postBodySpec.bodyValue(any())).thenReturn(postHeadersSpec);
        when(postHeadersSpec.retrieve()).thenReturn(postResponseSpec);
        when(postResponseSpec.toEntity(String.class))
                .thenReturn(Mono.just(new ResponseEntity<>("error", HttpStatus.BAD_REQUEST)));

        // Ejecutar método
        ResponseEntity<String> response = usuarioService.crearUsuario(dto);

        // Verificar que devuelve 500 INTERNAL_SERVER_ERROR
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertTrue(response.getBody().contains("Error al crear usuario"));
    }

    // 🔹 Test eliminar usuario OK
    @Test
    void testEliminarUsuario_ok() {
        UsuarioService spyService = spy(usuarioService);
        String uuid = UUID.randomUUID().toString();
        doReturn(uuid).when(spyService).obtenerUserId(anyString(), anyString());

        Usuario user = new Usuario();
        user.setId(UUID.fromString(uuid));
        user.setFechaRegistro(LocalDateTime.now());
        when(usuarioRepository.findById(UUID.fromString(uuid)))
                .thenReturn(Optional.of(user));

        doNothing().when(usuarioRepository).deleteById(UUID.fromString(uuid));

        // Mock eliminarUsuarioEnKeycloak
        doNothing().when(spyService).eliminarUsuarioEnKeycloak(anyString(), anyString());

        ResponseEntity<String> response = spyService.eliminarUsuario("testUser");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Usuario eliminado correctamente", response.getBody());
    }

    // 🔹 Test cambiar rol
    @Test
    void testCambiarRolUsuarioConToken() {
        UsuarioService spyService = spy(usuarioService);
        doNothing().when(spyService).cambiarRolUsuario(anyString(), anyString(), anyString());

        spyService.cambiarRolUsuarioConToken("123", "ADMIN");

        verify(spyService, times(1)).cambiarRolUsuario("123", "ADMIN", "fake-token");
    }

    // 🔹 Test listar usuarios vacío
    @Test
    void testListarUsuarios_vacio() {
        UsuarioService spyService = spy(usuarioService);

        WebClient.RequestHeadersUriSpec request = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.get()).thenReturn(request);
        when(request.uri(anyString())).thenReturn(request);
        when(request.header(anyString(), anyString())).thenReturn(request);
        when(request.retrieve()).thenReturn(responseSpec);

        when(responseSpec.bodyToFlux(any(ParameterizedTypeReference.class)))
                .thenReturn(Flux.empty());

        ResponseEntity<List<UsuarioResponseDTO>> response = spyService.listarUsuarios();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().isEmpty());
    }

    // 🔹 Test listar usuarios por rol
    @Test
    void testListarUsuariosPorRol() {
        UsuarioResponseDTO dto = new UsuarioResponseDTO(
                "id123", "user", "mail@test.com", "RS", List.of("ADMIN"));

        UsuarioService spyService = spy(usuarioService);
        doReturn(ResponseEntity.ok(List.of(dto))).when(spyService).listarUsuarios();

        ResponseEntity<List<UsuarioResponseDTO>> response = spyService.listarUsuariosPorRol("ADMIN");

        assertEquals(1, response.getBody().size());
        assertEquals("user", response.getBody().get(0).getUsername());
    }
}
