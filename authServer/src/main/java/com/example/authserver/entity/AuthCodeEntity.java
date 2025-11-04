package com.example.authserver.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.security.Principal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthCodeEntity {
    private String authorizationId;
    private String registeredClientId;
    private String principalName;
    private Principal principal;
    private OAuth2AuthorizationRequest authorizationRequest;
    private Set<String> scopes;
    private String code;
    private Instant issuedAt;
    private Instant expiresAt;
}
