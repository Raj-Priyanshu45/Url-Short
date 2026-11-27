package com.self.authService.jwt;

import com.self.authService.enums.Provider;
import com.self.authService.enums.Roles;
import com.self.authService.enums.TokenType;
import com.self.authService.model.UserIdentity;
import com.self.authService.model.Users;
import com.self.authService.repo.AuthRepo;
import com.self.authService.repo.TokenRepo;
import com.self.authService.repo.UserIdentityRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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
    private final UserIdentityRepo identityRepo;

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

        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

        String googleSub = oidcUser.getSubject();
        String email = oidcUser.getEmail();

        Boolean emailVerified = oidcUser.getEmailVerified();

        if (email == null || email.isBlank()) {
            response.sendRedirect(
                    frontend + "/login?error=email_unavailable"
            );
            return;
        }

        if (googleSub == null || googleSub.isBlank()) {
            response.sendRedirect(
                    frontend + "/login?error=invalid_google_request"
            );
            return;
        }

        if (!Boolean.TRUE.equals(emailVerified)) {
            response.sendRedirect(
                    frontend + "/login?error=email_unverified"
            );
            return;
        }

        UserIdentity userIdentity = identityRepo.findByProviderAndProviderSubject(
                Provider.GOOGLE , googleSub).orElse(null);

        if (userIdentity == null) {

            Boolean existingUser = authRepo
                    .existsByEmailIgnoreCase(email);

            if (existingUser) {
                response.sendRedirect(
                        frontend + "/login?error=account_link_required"
                );
                return;
            }

            Users newUser = Users.builder()
                    .email(email)
                    .emailVerified(true)
                    .roles(Roles.USER)
                    .username(UUID.randomUUID().toString())
                    .passwordHash(UUID.randomUUID().toString())
                    .build();

            authRepo.save(newUser);

            userIdentity = UserIdentity.builder()
                    .provider(Provider.GOOGLE)
                    .providerSubject(googleSub)
                    .user(newUser)
                    .build();

            identityRepo.save(userIdentity);
        }

        Users user = userIdentity.getUser();

        String accessToken = jwtCreation.generateAccessToken(user);
        String refreshToken = jwtCreation.rawRefreshToken();
        String hashRefreshToken = jwtCreation.hashRefreshToken(refreshToken);

        setCookies.setCookies(response , accessToken , refreshToken);

        tokenRepo.save(
                com.self.authService.model.RefreshToken.builder()
                        .token(hashRefreshToken)
                        .type(TokenType.REFRESH)
                        .userId(user.getUserId())
                        .expTime(LocalDateTime.now().plusDays(ExpTime))
                        .build()
        );

        response.sendRedirect(
                frontend + "/home"
        );
    }
}
