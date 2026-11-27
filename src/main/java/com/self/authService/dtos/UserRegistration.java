package com.self.authService.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UserRegistration(
        @NotBlank
        @Size(min = 3, max = 30)
        String username,

        @NotBlank
        @Size(min = 12, max = 128)
        String password,

        @NotBlank
        @Email
        @Size(max = 254)
        String email
) {}