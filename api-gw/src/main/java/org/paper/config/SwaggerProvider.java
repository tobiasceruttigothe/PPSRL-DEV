package org.paper.config;

import org.springdoc.core.properties.AbstractSwaggerUiConfigProperties;
import org.springdoc.core.properties.SwaggerUiConfigProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

import java.util.HashSet;
import java.util.Set;

@Configuration
public class SwaggerProvider {

    @Value("${api-gw.url-microservicio-usuarios}")
    private String usersServiceUrl;

    /**
     * Configura las URLs de los microservicios para Swagger UI.
     * Este bean se ejecuta después de que todas las rutas estén configuradas.
     */
    @Bean
    @Lazy(false)
    public Set<AbstractSwaggerUiConfigProperties.SwaggerUrl> swaggerUrls(
            SwaggerUiConfigProperties swaggerUiConfig,
            RouteLocator routeLocator) {

        Set<AbstractSwaggerUiConfigProperties.SwaggerUrl> urls = new HashSet<>();

        // Agregar documentación del microservicio de usuarios
        AbstractSwaggerUiConfigProperties.SwaggerUrl usersUrl =
                new AbstractSwaggerUiConfigProperties.SwaggerUrl();
        usersUrl.setName("Users Service");
        usersUrl.setUrl("/usuarios-docs");
        urls.add(usersUrl);

        // Log para debug
        System.out.println("📚 Swagger URLs configuradas:");
        urls.forEach(url -> System.out.println("   - " + url.getName() + ": " + url.getUrl()));

        return urls;
    }
}