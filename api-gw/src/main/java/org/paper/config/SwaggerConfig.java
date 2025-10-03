package org.paper.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class SwaggerConfig {

    @Bean
    //@Primary
    public RouteLocator swaggerRoutes(
            RouteLocatorBuilder builder,
            @Value("${api-gw.url-microservicio-usuarios}") String uriUsuarios) {

        return builder.routes()
                // Ruta para el microservicio de usuarios
                .route("usuarios-service", r -> r
                        .path("/api/usuarios/**", "/api/auth/**")
                        .uri(uriUsuarios))

                // Ruta para exponer la documentación OpenAPI del microservicio de usuarios
                .route("usuarios-docs", r -> r
                        .path("/usuarios-docs")
                        .filters(f -> f.rewritePath("/usuarios-docs", "/v3/api-docs"))
                        .uri(uriUsuarios))

                .build();
    }
}