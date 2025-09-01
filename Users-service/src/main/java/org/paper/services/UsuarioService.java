package org.paper.services;


import org.paper.DAO.UsuarioDAO;
import org.springframework.http.*;
        import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class UsuarioService {

    private final KeycloakAdminService keycloakAdminService;
    private final RestTemplate restTemplate = new RestTemplate();

    public UsuarioService(KeycloakAdminService keycloakAdminService) {
        this.keycloakAdminService = keycloakAdminService;
    }

    public ResponseEntity<String> crearUsuario(UsuarioDAO usuario) {
        String token = keycloakAdminService.getAdminToken();

        // Construir JSON para Keycloak sin password (se hace en reset-password)
        String jsonBody = String.format(
                "{ \"username\":\"%s\", \"enabled\":%b, \"firstName\":\"%s\", \"lastName\":\"%s\", \"email\":\"%s\", \"emailVerified\":%b }",
                usuario.getUsername(),
                usuario.isEnabled(),
                usuario.getFirstName(),
                usuario.getLastName(),
                usuario.getEmail(),
                usuario.isEmailVerified()
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        HttpEntity<String> request = new HttpEntity<>(jsonBody, headers);
        String url = "http://localhost:8080/admin/realms/tesina/users";
        ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);

        // Si se creó correctamente, asignar contraseña
        if (response.getStatusCode().is2xxSuccessful() && usuario.getPassword() != null) {
            asignarPassword(usuario, token);
        }

        return response;
    }

    private void asignarPassword(UsuarioDAO usuario, String token) {
        // Obtener ID del usuario recién creado
        String searchUrl = "http://localhost:8080/admin/realms/tesina/users?username=" + usuario.getUsername();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<Object[]> searchResponse = restTemplate.exchange(searchUrl, HttpMethod.GET, entity, Object[].class);
        if (searchResponse.getBody() != null && searchResponse.getBody().length > 0) {
            String userId = (String) ((java.util.LinkedHashMap) searchResponse.getBody()[0]).get("id");

            // Endpoint para reset-password
            String passwordUrl = "http://localhost:8080/admin/realms/tesina/users/" + userId + "/reset-password";

            String passwordJson = String.format("{\"type\":\"password\",\"value\":\"%s\",\"temporary\":false}", usuario.getPassword());
            HttpHeaders pwdHeaders = new HttpHeaders();
            pwdHeaders.setContentType(MediaType.APPLICATION_JSON);
            pwdHeaders.setBearerAuth(token);

            HttpEntity<String> pwdRequest = new HttpEntity<>(passwordJson, pwdHeaders);
            restTemplate.exchange(passwordUrl, HttpMethod.PUT, pwdRequest, String.class);
        }
    }
}

