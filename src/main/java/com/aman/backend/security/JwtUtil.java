package com.aman.backend.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    // ==========================================
    // Read secret from application.properties
    // ==========================================
    @Value("${jwt.secret}")
    private String secret;

    private SecretKey secretKey;

    // ==========================================
    // Create SecretKey only once
    // ==========================================
    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    // ==========================================
    // Token validity (24 hours)
    // ==========================================
    private static final long EXPIRATION_TIME =
            1000 * 60 * 60 * 24;

    // ==========================================
    // Generate JWT
    // ==========================================
    public String generateToken(String email) {

        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // ==========================================
    // Extract Username (Email)
    // ==========================================
    public String extractUsername(String token) {

        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    // ==========================================
    // Validate Token
    // ==========================================
    public boolean validateToken(String token, String email) {

        return extractUsername(token).equals(email);
    }
}