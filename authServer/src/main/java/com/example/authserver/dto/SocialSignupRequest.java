package com.example.authserver.dto;

public record SocialSignupRequest(
        String provider,
        String providerId,
        String email,
        String name,
        String phone
) {
}

