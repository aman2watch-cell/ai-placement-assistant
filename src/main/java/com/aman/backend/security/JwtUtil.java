package com.aman.backend.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    // Secret key used to sign JWT
    private final SecretKey SECRET_KEY =
            Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // Token validity (24 hours)
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24;

    // ==========================
    // Generate JWT Token
    // ==========================
    public String generateToken(String email) {

        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    // ==========================
    // Extract Email from Token
    // ==========================
    public String extractEmail(String token) {

        Claims claims = Jwts.parser()
                .verifyWith(SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    // ==========================
    // Validate Token
    // ==========================
    public boolean validateToken(String token, String email) {

        String extractedEmail = extractEmail(token);

        return extractedEmail.equals(email);
    }
}