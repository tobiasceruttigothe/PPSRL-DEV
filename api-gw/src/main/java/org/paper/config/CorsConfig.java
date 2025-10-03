package org.paper.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        // Orígenes permitidos
        corsConfig.setAllowedOrigins(List.of(
                "http://localhost:5173"
                //dev todos pueden acceder
                ,"*"
                // En producción, agregar dominio real:

        ));

        // Métodos HTTP permitidos
        corsConfig.setAllowedMethods(Arrays.asList(
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "OPTIONS",
                "PATCH"
        ));

        // Headers permitidos
        corsConfig.setAllowedHeaders(List.of("*"));

        // Permitir envío de credenciales (cookies, Authorization header)
        corsConfig.setAllowCredentials(true);

        // Headers expuestos al cliente
        corsConfig.setExposedHeaders(Arrays.asList(
                "Authorization",
                "X-Correlation-Id"
        ));

        // Tiempo de caché de la respuesta preflight (en segundos)
        corsConfig.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig); // Aplicar a todas las rutas

        return new CorsWebFilter(source);
    }
}