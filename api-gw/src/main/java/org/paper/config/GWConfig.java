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
                                        @Value("${api-gw.url-microservicio-notificaciones}") String uriNotificaciones,
                                        @Value("${api-gw.url-microservicio-pruebas}") String uriPruebas,
                                        @Value("${api-gw.url-microservicio-vehiculos}") String uriVehiculos,
                                        @Value("${api-gw.url-microservicio-reportes}") String uriReportes) {
        return builder.routes()
                // Ruteo al Microservicio de Notificaciones
                .route(p -> p.path("/api/notificaciones/**").uri(uriNotificaciones))
                // Ruteo al Microservicio de Pruebas de vehiculos
                .route(p -> p.path("/api/pruebas/**").uri(uriPruebas))
                // Ruteo al Microservicio de vehiculos
                .route(p -> p.path("/api/vehiculos/**").uri(uriVehiculos))
                //.route(p -> p.path("/api/marcas/**").uri(uriVehiculos))

                // Ruteo al Microservicio de Reportes
                .route(p -> p.path("/api/reportes/**").uri(uriReportes))
                .build();

    }

}
