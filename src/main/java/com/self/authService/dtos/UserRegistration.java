package com.self.authService.dtos;

public record UserRegistration(
        String username ,
        String password ,
        String email
) {
}
