package org.paper.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Configuration
public class CustomHeadersConfig {

    @Bean
    public GlobalFilter customHeadersFilter() {
        return (exchange, chain) -> {
            return exchange.getPrincipal()
                    .filter(principal -> principal instanceof JwtAuthenticationToken)
                    .cast(JwtAuthenticationToken.class)
                    .map(auth -> {
                        Jwt jwt = auth.getToken();

                        String userId = jwt.getSubject(); // "sub"
                        String username = jwt.getClaimAsString("preferred_username");

                        // Extraer roles de realm_access.roles
                        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                        List<String> roles = realmAccess != null
                                ? (List<String>) realmAccess.get("roles")
                                : List.of();

                        ServerHttpRequest request = exchange.getRequest().mutate()
                                .header("X-User-Id", userId)
                                .header("X-User-Username", username != null ? username : "")
                                .header("X-User-Roles", String.join(",", roles))
                                .build();

                        return exchange.mutate().request(request).build();
                    })
                    .switchIfEmpty(Mono.just(exchange))  // Si no hay JWT, continuar sin headers
                    .flatMap(chain::filter);
        };
    }
}