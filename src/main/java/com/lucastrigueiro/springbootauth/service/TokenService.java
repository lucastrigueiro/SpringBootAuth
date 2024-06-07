package com.lucastrigueiro.springbootauth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.lucastrigueiro.springbootauth.domain.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    @Value("${api.security.token.expiration}")
    private Long expiration;

    @Value("${api.security.token.issuer}")
    private String issuer;

    public String generateToken(User user) {
        try {
            var algorithm = Algorithm.HMAC256(secret);
            return JWT.create()
                .withIssuer(issuer)
                .withSubject(user.getLogin())
                .withExpiresAt(expirationTime())
                .sign(algorithm);
        } catch (JWTCreationException exception){
            throw new RuntimeException("Error generating jwt token", exception);
        }
    }

    public String validateAndGetSubject(String tokenJWT) {
        try {
            var algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                .withIssuer(issuer)
                .build()
                .verify(tokenJWT)
                .getSubject();
        } catch (JWTVerificationException exception) {
            throw new RuntimeException("Invalid or expired JWT token");
        }
    }

    private Instant expirationTime() {
        return LocalDateTime.now().plusMinutes(expiration).toInstant(ZoneOffset.of("-03:00"));
    }

}
