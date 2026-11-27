package com.self.authService.dtos;

public record LoginRequest (
        String username ,
        String password
) {
}
