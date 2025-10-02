package org.paper.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.util.retry.Retry;

import java.time.Duration;

@Slf4j
@Configuration
public class WebClientConfig {

    @Bean
    public WebClient webClient(@Value("${keycloak.server-url}") String serverUrl) {
        return WebClient.builder()
                .baseUrl(serverUrl)
                .filter((request, next) -> {
                    // Log del request
                    log.debug("Haciendo request a: {} {}", request.method(), request.url());

                    return next.exchange(request)
                            // Retry en caso de errores transitorios
                            .retryWhen(Retry.backoff(3, Duration.ofSeconds(1))
                                    .maxBackoff(Duration.ofSeconds(5))
                                    // Solo reintentar en estos errores (transitorios)
                                    .filter(throwable -> {
                                        if (throwable instanceof WebClientResponseException) {
                                            WebClientResponseException ex = (WebClientResponseException) throwable;
                                            int status = ex.getStatusCode().value();
                                            // Reintentar en: 500, 502, 503, 504 (errores de servidor)
                                            // NO reintentar en: 400, 401, 404, 409 (errores del cliente)
                                            return status >= 500 && status < 600;
                                        }
                                        // También reintentar en errores de red (timeout, conexión)
                                        return throwable instanceof java.net.ConnectException
                                                || throwable instanceof java.util.concurrent.TimeoutException;
                                    })
                                    // Log cuando reintenta
                                    .doBeforeRetry(retrySignal -> {
                                        log.warn("Reintentando request (intento {}/3) debido a: {}",
                                                retrySignal.totalRetries() + 1,
                                                retrySignal.failure().getMessage());
                                    })
                                    // Cuando se agoten los reintentos
                                    .onRetryExhaustedThrow((retryBackoffSpec, retrySignal) -> {
                                        log.error("Se agotaron los 3 reintentos. Último error: {}",
                                                retrySignal.failure().getMessage());
                                        // Lanzar la excepción original
                                        return retrySignal.failure();
                                    })
                            );
                })
                .build();
    }
}