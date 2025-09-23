package org.paper.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GWConfig {

    @Bean
    public RouteLocator configurarRutas(RouteLocatorBuilder builder,
                                        @Value("${api-gw.url-microservicio-usuarios}") String uriUsuarios) {
        return builder.routes()
                .route(p -> p.path("/api/usuarios/**").uri(uriUsuarios))
                .build();
    }
}
