package org.paper.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
@Order(1) // Se ejecuta PRIMERO antes que otros filtros
public class CorrelationIdFilter implements Filter {

    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    private static final String CORRELATION_ID_MDC_KEY = "correlationId";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // Intenta obtener el correlationId del header (si viene de otro servicio)
        String correlationId = httpRequest.getHeader(CORRELATION_ID_HEADER);

        // Si no viene, genera uno nuevo
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = UUID.randomUUID().toString();
        }

        // Lo pone en el MDC para que todos los logs lo incluyan
        MDC.put(CORRELATION_ID_MDC_KEY, correlationId);

        log.debug("Request recibido: {} {} [correlationId={}]",
                httpRequest.getMethod(),
                httpRequest.getRequestURI(),
                correlationId);

        try {
            // Continúa con el resto de filtros y el controller
            chain.doFilter(request, response);
        } finally {
            // IMPORTANTE: Limpiar el MDC después del request
            MDC.clear();
        }
    }
}