package org.paper.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Paper SRL - API Gateway")
                        .version("1.0.0")
                        .description("""
                            API centralizada del backend de Paper SRL.
                            
                            ## Autenticación
                            
                            Todos los endpoints (excepto los públicos) requieren autenticación mediante Bearer Token (JWT).
                            
                            ### Obtener token:
```bash
                            curl -X POST 'http://localhost:8080/realms/tesina/protocol/openid-connect/token' \\
                              -H 'Content-Type: application/x-www-form-urlencoded' \\
                              -d 'client_id=backend-service' \\
                              -d 'client_secret=siZIjoNYryGmXBPAhafsYMTyW0WtnU6z' \\
                              -d 'grant_type=password' \\
                              -d 'username=TU_USUARIO' \\
                              -d 'password=TU_CONTRASEÑA'
                              ### Usar el token:
                        
                        Agregar el header: `Authorization: Bearer {access_token}`
                        
                        ## Microservicios
                        
                        - **Users Service**: Gestión de usuarios y autenticación
                        """)
                        .contact(new Contact()
                                .name("Equipo Backend Paper SRL")
                                .email("backend@papersrl.com")
                                .url("https://github.com/tobiasceruttigothe/PAPERSRL-BACKEND"))
                        .license(new License()
                                .name("Privado")
                                .url("https://papersrl.com")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:9090")
                                .description("Servidor local"),
                        new Server()
                                .url("http://api-gateway:9090")
                                .description("Servidor Docker")
                ))
                .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
                .components(new Components()
                        .addSecuritySchemes("Bearer Authentication",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Ingresá el token JWT obtenido desde Keycloak (sin el prefijo 'Bearer')")));
    }
}