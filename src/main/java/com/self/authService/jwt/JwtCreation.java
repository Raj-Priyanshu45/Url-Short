package com.self.authService.jwt;

import com.self.authService.model.Users;
import com.self.authService.repo.AuthRepo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;

import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;

@Component
@RequiredArgsConstructor
public class JwtCreation {

    @Value("Jwt.Secret")
    private String Secret;

    @Value("Jwt.Exp")
    private long ExpTime;

    private SecretKey secretKey;

    private final AuthRepo authRepo;

    @PostConstruct
    void init(){
        secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(Secret));
    }

    public String generateAccessToken(Users user) {
        long Exp = ExpTime;

        return Jwts.builder()
                .subject(user.getUserId())
                .claim("Role" , user.getRoles().name())
                .claim("Provider" , user.getProvider().name())
                .claim("Email_Verified" , user.isEmailVerified())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + Exp))
                .signWith(secretKey)
                .compact();
    }

    public String rawRefreshToken(){
        return UUID.randomUUID().toString() + UUID.randomUUID();
    }

    public String hashRefreshToken(String refreshToken) {

        if (refreshToken == null) throw new IllegalArgumentException("Refresh Token can not be Empty");

        try{

            byte[] hash = MessageDigest
                    .getInstance("SHA-256")
                    .digest(refreshToken.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
