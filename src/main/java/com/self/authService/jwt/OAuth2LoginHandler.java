package com.self.authService.jwt;

import com.self.authService.enums.Provider;
import com.self.authService.enums.Roles;
import com.self.authService.enums.TokenType;
import com.self.authService.model.RefreshToken;
import com.self.authService.model.Users;
import com.self.authService.repo.AuthRepo;
import com.self.authService.repo.TokenRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2LoginHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final TokenRepo tokenRepo;
    private final JwtCreation jwtCreation;
    private final SetCookies setCookies;
    private final AuthRepo authRepo;

    @Value("${App.Frontend}")
    private String frontend;

    @Value("${Jwt.Ref-Exp}")
    private long ExpTime;

    @Override
    public void onAuthenticationSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication
    ) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");

        if (email == null || email.isBlank()) {
            response.sendRedirect(
                    frontend + "/login?error=email_unavailable"
            );
            return;
        }

        Users user = authRepo.findByEmail(email).orElse(null);

        if (user == null) {
            user = Users.builder()
                    .email(email)
                    .emailVerified(true)
                    .provider(com.self.authService.enums.Provider.Google)
                    .roles(Roles.User)
                    .username(UUID.randomUUID().toString())
                    .build();
            authRepo.save(user);
        }

        String AccessToken = jwtCreation.generateAccessToken(user);
        String RefreshToken = jwtCreation.rawRefreshToken();
        String hashRefreshToken = jwtCreation.hashRefreshToken(RefreshToken);

        setCookies.setCookies(response , AccessToken , RefreshToken);

        tokenRepo.save(
                com.self.authService.model.RefreshToken.builder()
                        .token(hashRefreshToken)
                        .type(TokenType.RefreshToken)
                        .userId(user.getUserId())
                        .expTime(LocalDateTime.now().plusDays(ExpTime))
                        .build()
        );

        response.sendRedirect(
                frontend + "/home"
        );
    }
}
