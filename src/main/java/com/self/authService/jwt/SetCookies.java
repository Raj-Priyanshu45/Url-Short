package com.self.authService.jwt;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;


@Component
public class SetCookies {

    @Value("${Jwt.Exp}")
    private long ExpTime;

    @Value("${Jwt.Ref-Exp}")
    private long RefreshExp;

    public void setCookies (HttpServletResponse response , String accessToken , String refreshToken) {

        ResponseCookie access = ResponseCookie.from("JWT" , accessToken)
                .httpOnly(true)
                .maxAge(Duration.ofMillis(ExpTime))
                .secure(true)
                .sameSite("Lax")
                .path("/")
                .build();

        ResponseCookie refresh = ResponseCookie.from("REFRESH" , refreshToken)
                .httpOnly(true)
                .sameSite("Lax")
                .path("/auth/refresh")
                .maxAge(Duration.ofDays(RefreshExp))
                .secure(true)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE , access.toString());
        response.addHeader(HttpHeaders.SET_COOKIE , refresh.toString());
    }


    public void clearCookies (HttpServletResponse response) {

        ResponseCookie access = ResponseCookie.from("JWT" , "")
                .httpOnly(true)
                .maxAge(Duration.ofMillis(0))
                .secure(true)
                .sameSite("Lax")
                .path("/")
                .build();

        ResponseCookie refresh = ResponseCookie.from("REFRESH" , "")
                .httpOnly(true)
                .sameSite("Lax")
                .path("/auth/refresh")
                .maxAge(Duration.ofDays(0))
                .secure(true)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE , access.toString());
        response.addHeader(HttpHeaders.SET_COOKIE , refresh.toString());
    }
}
