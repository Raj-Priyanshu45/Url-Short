package com.self.authService.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    @GetMapping("/csrf")
    public ResponseEntity<Void> getCsrfToken(CsrfToken csrfToken) {

        csrfToken.getToken();
        return ResponseEntity.noContent().build();
    }
}
