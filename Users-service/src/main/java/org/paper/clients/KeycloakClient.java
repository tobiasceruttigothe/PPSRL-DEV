package org.paper.clients;

import lombok.extern.slf4j.Slf4j;
import org.paper.dto.UsuarioCreateDTO;
import org.paper.exception.KeycloakException;
import org.paper.exception.ValidationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class KeycloakClient {

    private final WebClient webClient;
    private final String realm;

    public KeycloakClient(WebClient webClient, @Value("${keycloak.realm}") String realm) {
        this.webClient = webClient;
        this.realm = realm;
    }

    public String obtenerUserId(String username, String token) {
        try {
            List<Map<String, Object>> users = webClient.get()
                    .uri("/admin/realms/{realm}/users?username={username}", realm, username)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .collectList()
                    .block();

            if (users == null || users.isEmpty()) {
                return null;
            }
            if (users.size() > 1) {
                throw new ValidationException("username", "Múltiples usuarios encontrados con el mismo nombre");
            }
            return (String) users.get(0).get("id");
        } catch (WebClientResponseException e) {
            throw new KeycloakException("obtener usuario", e.getStatusCode().value(), e.getResponseBodyAsString());
        }
    }

    public void crearUsuario(UsuarioCreateDTO usuario, String token) {
        String jsonBody = String.format(
            "{ \"username\":\"%s\", \"enabled\":%b, \"email\":\"%s\", \"emailVerified\":%b, \"attributes\": { \"razonSocial\": [\"%s\"] } }",
            usuario.getUsername(), usuario.isEnabled(), usuario.getEmail(), usuario.isEmailVerified(), usuario.getRazonSocial()
        );
        try {
            webClient.post()
                .uri("/admin/realms/{realm}/users", realm)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(jsonBody)
                .retrieve()
                .toBodilessEntity()
                .block();
        } catch (WebClientResponseException e) {
            throw new KeycloakException("crear usuario", e.getStatusCode().value(), e.getResponseBodyAsString());
        }
    }

    public void asignarPassword(String userId, String password, String token) {
        String passwordJson = String.format("{\"type\":\"password\",\"value\":\"%s\",\"temporary\":false}", password);
        try {
            webClient.put()
                .uri("/admin/realms/{realm}/users/{id}/reset-password", realm, userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(passwordJson)
                .retrieve()
                .toBodilessEntity()
                .block();
        } catch (WebClientResponseException e) {
            throw new KeycloakException("asignar password", e.getStatusCode().value(), "No se pudo asignar la contraseña");
        }
    }

    public void eliminarUsuario(String userId, String token) {
        try {
            webClient.delete()
                .uri("/admin/realms/{realm}/users/{id}", realm, userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .toBodilessEntity()
                .block();
        } catch (WebClientResponseException e) {
            throw new KeycloakException("eliminar usuario", e.getStatusCode().value(), "No se pudo eliminar el usuario de Keycloak");
        }
    }

    public List<Map<String, Object>> listarUsuarios(String token) {
        return webClient.get()
            .uri("/admin/realms/{realm}/users", realm)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .retrieve()
            .bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {})
            .collectList()
            .block();
    }

    public List<Map<String, Object>> listarRolesDeUsuario(String userId, String token) {
        return webClient.get()
            .uri("/admin/realms/{realm}/users/{userId}/role-mappings/realm", realm, userId)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .retrieve()
            .bodyToFlux(new ParameterizedTypeReference<Map<String, Object>>() {})
            .collectList()
            .block();
    }

    public void eliminarRolesDeUsuario(String userId, List<Map<String, Object>> roles, String token) {
        webClient.method(HttpMethod.DELETE)
            .uri("/admin/realms/{realm}/users/{userId}/role-mappings/realm", realm, userId)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .bodyValue(roles)
            .retrieve()
            .toBodilessEntity()
            .block();
    }

    public Map<String, Object> obtenerRolPorNombre(String roleName, String token) {
        return webClient.get()
            .uri("/admin/realms/{realm}/roles/{roleName}", realm, roleName)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .retrieve()
            .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
            .block();
    }

    public void agregarRolesAUsuario(String userId, List<Map<String, Object>> roles, String token) {
        webClient.post()
            .uri("/admin/realms/{realm}/users/{userId}/role-mappings/realm", realm, userId)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .bodyValue(roles)
            .retrieve()
            .toBodilessEntity()
            .block();
    }
}