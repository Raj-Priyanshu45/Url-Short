package com.self.authService.jwt;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtCreation jwtCreation;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        String token = extractCookie(request , "JWT");

        if (token == null) {
            filterChain.doFilter(request , response);
        }

        Claims claims = jwtCreation.parse(token);

        String userid = claims.getSubject();
        String role = claims.get("Role" , String.class);
        String provider = claims.get("Provider" , String.class);
        String email = claims.get("Email_Verified" , String.class);

        List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
        grantedAuthorityList.add(new SimpleGrantedAuthority("ROLE_" + role));
        grantedAuthorityList.add(new SimpleGrantedAuthority("PROVIDER_"+provider));
        grantedAuthorityList.add(new SimpleGrantedAuthority("EMAIL_"+email));

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userid ,
                null ,
                grantedAuthorityList
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request , response);
    }

    public String extractCookie(HttpServletRequest request , String name) {

        if (request.getCookies() == null) {
            return null;
        }

        for (Cookie cookie : request.getCookies()) {

            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        return path.equals("/auth/register");
    }
}
