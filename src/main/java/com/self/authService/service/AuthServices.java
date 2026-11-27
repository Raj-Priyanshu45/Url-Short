package com.self.authService.service;

import com.self.authService.dtos.UserRegistration;
import com.self.authService.enums.LoginReqStatus;
import com.self.authService.enums.Provider;
import com.self.authService.enums.Roles;
import com.self.authService.enums.TokenType;
import com.self.authService.jwt.JwtCreation;
import com.self.authService.jwt.JwtFilter;
import com.self.authService.jwt.SetCookies;
import com.self.authService.model.RefreshToken;
import com.self.authService.model.UserIdentity;
import com.self.authService.model.Users;
import com.self.authService.repo.AuthRepo;
import com.self.authService.repo.TokenRepo;
import com.self.authService.repo.UserIdentityRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServices {

    private final AuthRepo authRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtCreation jwtCreation;
    private final SetCookies setCookies;
    private final TokenRepo tokenRepo;
    private final UserIdentityRepo identityRepo;
    private final JwtFilter jwtFilter;

    @Value("${Jwt.Ref-Exp}")
    private long expTime;

    @Value("${App.Frontend}")
    private String frontend;

    @Transactional
    public LoginReqStatus login(HttpServletResponse response , String username , String password) {

        if (username.isBlank() || password.isEmpty()) return LoginReqStatus.Invalid_request;

        Users user = authRepo.findByUsername(username).orElse(null);

        if (user == null) return LoginReqStatus.User_does_not_exists;

        String passwordHash = user.getPasswordHash();

        if (passwordHash == null || passwordHash.isBlank()) {
            return LoginReqStatus.Account_not_linked;
        }

        if (!passwordEncoder.matches(
                password ,
                user.getPasswordHash()
        )) {
            return LoginReqStatus.Unauthorized;
        }

        setTokens(response , user);

        return LoginReqStatus.Success;
    }

    @Transactional
    public LoginReqStatus registerUser(HttpServletResponse response , UserRegistration registration) throws IOException {

        if (registration.email().isEmpty()
                || registration.password().isEmpty()
                || registration.username().isEmpty()
        ) {
            return LoginReqStatus.Invalid_request;
        }

        if (authRepo.existsByEmailIgnoreCase(registration.email())) return LoginReqStatus.User_already_exists;

        if (authRepo.existsByUsername(registration.username())) return LoginReqStatus.User_already_exists;


        Users user = Users.builder()
                .username(registration.username())
                .roles(Roles.USER)
                .email(registration.email().trim().toLowerCase(Locale.ROOT))
                .passwordHash(
                        passwordEncoder.encode(registration.password())
                )
                .emailVerified(false)
                .build();
        authRepo.save(user);

        UserIdentity userIdentity = UserIdentity.builder()
                .user(user)
                .providerSubject(user.getUserId())
                .provider(Provider.APP)
                .build();
        identityRepo.save(userIdentity);

        setTokens(response , user);

        response.sendRedirect(
                frontend + "/verify-email"
        );

        return LoginReqStatus.Success;
    }

    private void setTokens(HttpServletResponse response , Users user) {

        String accessToken = jwtCreation.generateAccessToken(user);
        String refreshToken = jwtCreation.rawRefreshToken();
        String refreshTokenHash = jwtCreation.hashRefreshToken(refreshToken);


        RefreshToken token = RefreshToken.builder()
                .expTime(Instant.now().plus(expTime , ChronoUnit.DAYS))
                .userId(user.getUserId())
                .type(TokenType.REFRESH)
                .token(refreshTokenHash)
                .build();

        tokenRepo.save(token);
        setCookies.setCookies(response, accessToken, refreshToken);
    }

    public boolean rotateRefreshToken(HttpServletRequest request , HttpServletResponse response) {

        String refresh = jwtFilter.extractCookie(request , "REFRESH");

        if (refresh == null) return false;

        RefreshToken token = tokenRepo.findByTokenAndType(
                jwtCreation.hashRefreshToken(refresh) ,
                 TokenType.REFRESH).orElse(null);

        if (token == null) return false;

        if (!token.getExpTime().isAfter(Instant.now())) {
            tokenRepo.delete(token);
            return false;
        }

        tokenRepo.delete(token);

        Users user = authRepo.findByUserId(token.getUserId());

        setTokens(response , user);

        return true;
    }

    @Transactional
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        String refresh = jwtFilter.extractCookie(request, "REFRESH");

        if (refresh != null && !refresh.isBlank()) {

            String hash = jwtCreation.hashRefreshToken(refresh);

            tokenRepo.deleteByTokenAndType(
                    hash,
                    TokenType.REFRESH
            );
        }

        setCookies.clearCookies(response);
    }

    @Scheduled(cron = "0 0 2 * * *", zone = "UTC")
    @Transactional
    public void cleanupExpiredTokens() {

        log.info("Starting expired refresh token cleanup");

        tokenRepo
                .deleteAllByExpTimeBefore(Instant.now());

        log.info("Expired refresh token cleanup completed");
    }
}
