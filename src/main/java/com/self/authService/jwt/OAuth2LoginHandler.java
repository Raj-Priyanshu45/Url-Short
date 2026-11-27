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

        assert oidcUser != null;
        String googleSub = oidcUser.getSubject();
        String email = oidcUser.getEmail();

        Boolean emailVerified = oidcUser.getEmailVerified();

        if (email == null || email.isBlank()) {
            response.sendRedirect(
                    frontend + "/login?error=email_unavailable"
            );
            return;
        }

        Users user = authRepo.findByEmailIgnoreCase(email).orElse(null);

        if (user == null) {
            user = Users.builder()
                    .email(email)
                    .emailVerified(emailVerified)
                    .roles(Roles.USER)
                    .username(UUID.randomUUID().toString())
                    .build();
            authRepo.save(user);
        }

        UserIdentity userIdentity = identityRepo.findByProviderAndProviderSubject(
                Provider.GOOGLE , googleSub).orElse(null);

        if (userIdentity == null) {
            userIdentity = UserIdentity.builder()
                    .provider(Provider.GOOGLE)
                    .providerSubject(googleSub)
                    .user(user)
                    .build();

            identityRepo.save(userIdentity);
        }

        String AccessToken = jwtCreation.generateAccessToken(user);
        String RefreshToken = jwtCreation.rawRefreshToken();
        String hashRefreshToken = jwtCreation.hashRefreshToken(RefreshToken);

        setCookies.setCookies(response , AccessToken , RefreshToken);

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
