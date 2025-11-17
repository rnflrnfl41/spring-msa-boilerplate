package com.example.authserver.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.security.Principal;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

@Data
@Builder
public class TokenEntity {
    private String authorizationId;
    private String registeredClientId;
    private Principal principal;
    private String principalName;
    private OAuth2AuthorizationRequest authorizationRequest;
    private Set<String> scopes;

    private Set<String> accessTokenScopes;
    private String accessTokenValue;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;

    private String refreshTokenValue;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;

    private String idTokenValue;
    private Instant idTokenIssuedAt;
    private Instant idTokenExpiresAt;
    private Map<String,Object> idTokenClaims;
}
