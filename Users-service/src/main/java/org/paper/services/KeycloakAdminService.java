package org.paper.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;
@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakAdminService {

    private final WebClient webClient;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    private volatile String cachedToken;
    private volatile long tokenExpiryTime;

    public synchronized String getAdminToken() {
        // Verificar si el token aún es válido
        if (cachedToken != null && System.currentTimeMillis() < tokenExpiryTime) {
            log.debug("Usando token en caché (expira en {}ms)",
                    tokenExpiryTime - System.currentTimeMillis());
            return cachedToken;
        }

        log.info("Solicitando nuevo token de administrador a Keycloak");

        try {
            Map<String, Object> response = webClient.post()
                    .uri("/realms/{realm}/protocol/openid-connect/token", realm)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData("client_id", clientId)
                            .with("client_secret", clientSecret)
                            .with("grant_type", "client_credentials"))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (response == null || !response.containsKey("access_token")) {
                log.error("Respuesta inválida de Keycloak: {}", response);
                throw new RuntimeException("No se pudo obtener access_token de Keycloak");
            }

            cachedToken = (String) response.get("access_token");
            Integer expiresIn = (Integer) response.get("expires_in");

            // Restar 10 segundos para evitar usar un token a punto de expirar
            tokenExpiryTime = System.currentTimeMillis() + (expiresIn - 10) * 1000L;

            log.info("Token obtenido correctamente (válido por {} segundos)", expiresIn);

            return cachedToken;

        } catch (Exception e) {
            log.error("Error al obtener token de Keycloak: {}", e.getMessage(), e);
            throw new RuntimeException("No se pudo obtener token de administrador", e);
        }
    }



    //revisar

    public void marcarEmailComoVerificado(String userId, String token) {
        webClient.put()
                .uri("/admin/realms/tesina/users/{id}", userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("emailVerified", true))
                .retrieve()
                .toBodilessEntity()
                .block();

        log.info("Usuario {} marcado como email verificado en Keycloak", userId);
    }
}
