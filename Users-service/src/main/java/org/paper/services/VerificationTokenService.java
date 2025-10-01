package org.paper.services;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
@Slf4j
public class VerificationTokenService {

    private final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    @Value("${app.verification-token-expiration}")
    private String expiration; // ej: "24h"

    public String generarToken(String userId, String email) {
        Instant now = Instant.now();
        Instant exp = now.plus(24, ChronoUnit.HOURS); // configurable

        return Jwts.builder()
                .setSubject(userId)
                .claim("email", email)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(secretKey)
                .compact();
    }

    public String validarToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject(); // devuelve userId
        } catch (Exception e) {
            log.error("Token inválido o expirado: {}", e.getMessage());
            throw new RuntimeException("Token inválido o expirado");
        }
    }
}

