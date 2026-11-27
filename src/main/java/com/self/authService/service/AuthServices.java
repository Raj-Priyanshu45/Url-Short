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
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
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

    public LoginReqStatus login(HttpServletResponse response , String username , String password) {

        if (username.isBlank() || password.isEmpty()) return LoginReqStatus.Invalid_request;

        Users user = authRepo.findByUsername(username).orElse(null);

        if (user == null) return LoginReqStatus.User_does_not_exists;

        if (!passwordEncoder.matches(
                password ,
                user.getPasswordHash()
        )) {
            return LoginReqStatus.Unauthorized;
        }

        setTokens(response , user);

        return LoginReqStatus.Success;
    }

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
                .email(registration.email())
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

        setCookies.setCookies(response , accessToken , refreshToken);

        RefreshToken token = RefreshToken.builder()
                .expTime(LocalDateTime.now().plusDays(expTime))
                .userId(user.getUserId())
                .type(TokenType.REFRESH)
                .token(refreshTokenHash)
                .build();

        tokenRepo.save(token);
    }

    public boolean rotateRefreshToken(HttpServletRequest request , HttpServletResponse response) {

        String refresh = jwtFilter.extractCookie(request , "REFRESH");

        if (refresh == null) return false;

        RefreshToken token = tokenRepo.findByTokenAndType(refresh , TokenType.REFRESH).orElse(null);

        if (token == null) return false;

        if (token.getExpTime().isBefore(LocalDateTime.now())) return false;

        Users user = authRepo.findByUserId(token.getUserId());

        setTokens(response , user);

        return true;
    }
}
