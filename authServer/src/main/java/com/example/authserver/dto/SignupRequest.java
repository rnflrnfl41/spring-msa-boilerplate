package com.example.authserver.dto;

public record SignupRequest(
        String name,
        String loginId,
        String phone,
        String email,
        String password,
        String passwordConfirm
) {
}

