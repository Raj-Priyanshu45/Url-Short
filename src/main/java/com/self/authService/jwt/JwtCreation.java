package com.self.authService.jwt;

import com.self.authService.model.Users;
import com.self.authService.repo.AuthRepo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;

import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;

@Component
@RequiredArgsConstructor
public class JwtCreation {

    private final KeyPair keyPair;

    @Value("${Jwt.issuer}")
    private String issuer;

    @Value("${Jwt.audience}")
    private String audience;

    @Value("${Jwt.access-token-ttl-ms}")
    private long accessTokenTtl;

    private JwtParser jwtParser;

    private final AuthRepo authRepo;

    @PostConstruct
    void init() {
        jwtParser = Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .requireIssuer(issuer)
                .requireAudience(audience)
                .build();
    }


    public String generateAccessToken(Users user) {

        Instant instant = Instant.now();

        return Jwts.builder()
                .issuer(issuer)
                .subject(user.getUserId())
                .audience()
                .add(audience)
                .and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(accessTokenTtl)))
                .id(UUID.randomUUID().toString())
                .claim("Role" , user.getRoles().name())
                .claim("Provider" , user.getProvider().name())
                .claim("Email_Verified" , user.isEmailVerified())
                .signWith(
                        keyPair.getPrivate() ,
                        Jwts.SIG.RS256
                )
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

        return jwtParser
                .parseSignedClaims(token)
                .getPayload();
    }
}
