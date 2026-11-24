package com.self.authService.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JwtKeyConfig {

    @Bean
    public KeyPair jwtKeyPair(
            @Value("${Jwt.private-key-location}") Resource privateResource,
            @Value("${Jwt.public-key-location}") Resource publicResource
    ) throws Exception {

        byte[] privateKeyBytes = decodePem(privateResource);
        byte[] publicKeyBytes = decodePem(publicResource);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(privateKeyBytes)
        );

        PublicKey publicKey = keyFactory.generatePublic(
                new X509EncodedKeySpec(publicKeyBytes)
        );

        return new KeyPair(publicKey , privateKey);
    }

    private byte[] decodePem(Resource resource) throws IOException {

        try (InputStream input = resource.getInputStream()) {

            String pem = new String(
                    input.readAllBytes() ,
                    StandardCharsets.UTF_8
            );

            String base64 = pem
                    .replaceAll("-----BEGIN [^-]+-----", "")
                    .replaceAll("-----END [^-]+-----", "")
                    .replaceAll("\\s", "");

            return Base64.getDecoder().decode(base64);
        }
    }
}
