package org.paper.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "app.rate-limit")
public class RateLimitConfig {

    // Límites por defecto
    private long defaultCapacity = 20;
    private long defaultRefillTokens = 10;

    // Límites personalizados por ruta
    private Map<String, RouteLimit> routes = new HashMap<>();

    @Data
    public static class RouteLimit {
        private long capacity;
        private long refillTokens;
    }
}