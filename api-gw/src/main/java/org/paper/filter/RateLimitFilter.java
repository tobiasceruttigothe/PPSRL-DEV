package org.paper.filter;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;
import org.paper.config.RateLimitConfig;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class RateLimitFilter implements GlobalFilter, Ordered {

    // Cache con timestamp para limpieza
    private final Map<String, BucketWithTimestamp> cache = new ConcurrentHashMap<>();
    private final RateLimitConfig config;

    public RateLimitFilter(RateLimitConfig config) {
        this.config = config;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String clientId = getClientId(request);
        String path = request.getPath().value();

        // Crear clave única: IP + ruta (para límites por endpoint)
        String cacheKey = clientId + ":" + path;

        // Obtener o crear bucket y actualizar timestamp
        BucketWithTimestamp bucketWrapper = cache.computeIfAbsent(
                cacheKey,
                key -> new BucketWithTimestamp(createBucketForPath(path))
        );

        // Actualizar timestamp cada vez que se usa
        bucketWrapper.updateTimestamp();

        if (bucketWrapper.bucket.tryConsume(1)) {
            log.debug("Request permitido para {} en {}", clientId, path);
            return chain.filter(exchange);
        } else {
            log.warn("Rate limit excedido para {} en {}", clientId, path);

            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            response.getHeaders().add("X-Rate-Limit-Retry-After-Seconds", "1");

            // Agregar headers informativos
            response.getHeaders().add("X-Rate-Limit-Limit", String.valueOf(config.getDefaultCapacity()));
            response.getHeaders().add("X-Rate-Limit-Remaining", "0");

            return response.setComplete();
        }
    }

    /**
     * Limpia buckets inactivos cada 5 minutos
     * (Solo se ejecuta si @EnableScheduling está habilitado en ApiGateWay)
     */
    @Scheduled(fixedRate = 300000) // 5 minutos = 300,000 ms
    public void cleanupCache() {
        long now = System.currentTimeMillis();
        long expirationTime = 600000; // 10 minutos = 600,000 ms

        int initialSize = cache.size();

        cache.entrySet().removeIf(entry -> {
            boolean expired = (now - entry.getValue().timestamp) > expirationTime;
            if (expired) {
                log.debug("Removiendo bucket expirado para: {}", entry.getKey());
            }
            return expired;
        });

        int removedCount = initialSize - cache.size();
        if (removedCount > 0) {
            log.info("Cache limpiado: {} buckets removidos. Buckets activos: {}",
                    removedCount, cache.size());
        }
    }

    private Bucket createBucketForPath(String path) {
        // Buscar configuración específica para esta ruta
        for (Map.Entry<String, RateLimitConfig.RouteLimit> entry : config.getRoutes().entrySet()) {
            String pattern = entry.getKey();
            if (pathMatches(path, pattern)) {
                RateLimitConfig.RouteLimit limit = entry.getValue();
                log.debug("Aplicando límite personalizado para {}: capacity={}, refill={}",
                        path, limit.getCapacity(), limit.getRefillTokens());

                return Bucket.builder()
                        .addLimit(Bandwidth.classic(
                                limit.getCapacity(),
                                Refill.intervally(limit.getRefillTokens(), Duration.ofSeconds(1))
                        ))
                        .build();
            }
        }

        // Usar límites por defecto
        log.debug("Aplicando límite por defecto para {}", path);
        return Bucket.builder()
                .addLimit(Bandwidth.classic(
                        config.getDefaultCapacity(),
                        Refill.intervally(config.getDefaultRefillTokens(), Duration.ofSeconds(1))
                ))
                .build();
    }

    private boolean pathMatches(String path, String pattern) {
        // Soporte básico para wildcards
        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return path.startsWith(prefix);
        }
        return path.equals(pattern);
    }

    private String getClientId(ServerHttpRequest request) {
        String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isEmpty()) {
            return forwarded.split(",")[0].trim();
        }

        if (request.getRemoteAddress() != null) {
            return request.getRemoteAddress().getAddress().getHostAddress();
        }

        return "unknown";
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }

    /**
     * Clase interna que envuelve un Bucket con su timestamp
     * para poder saber cuándo fue usado por última vez
     */
    private static class BucketWithTimestamp {
        final Bucket bucket;
        long timestamp;

        BucketWithTimestamp(Bucket bucket) {
            this.bucket = bucket;
            this.timestamp = System.currentTimeMillis();
        }

        void updateTimestamp() {
            this.timestamp = System.currentTimeMillis();
        }
    }
}