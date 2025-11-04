package com.example.authserver.service;

import com.example.authserver.entity.AuthCodeEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.security.Principal;
import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RegisteredClientRepository clientRepository;
    private final ObjectMapper objectMapper;

    private static final String CODE_PREFIX = "oauth2:code:";
    private static final Duration CODE_TTL = Duration.ofMinutes(10);
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

    @Override
    public void save(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken = authorization.getToken(OAuth2AuthorizationCode.class);
        if (codeToken == null) return;

        OAuth2AuthorizationCode code = codeToken.getToken();

        OAuth2AuthorizationRequest authRequest =
                authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

        Authentication principal = authorization.getAttribute(Principal.class.getName());

        if (principal == null) {
            throw new IllegalStateException("Missing principal in authorization attributes");
        }

        if (authRequest == null) {
            throw new IllegalStateException("Missing OAuth2AuthorizationRequest in authorization attributes");
        }

        AuthCodeEntity entity = AuthCodeEntity.builder()
                .authorizationId(authorization.getId())
                .registeredClientId(authorization.getRegisteredClientId())
                .principal(principal)
                .principalName(authorization.getPrincipalName())
                .principal(principal)
                .authorizationRequest(authRequest)
                .scopes(authorization.getAuthorizedScopes())
                .code(code.getTokenValue())
                .issuedAt(code.getIssuedAt())
                .expiresAt(code.getExpiresAt())
                .build();

        redisTemplate.opsForValue().set(CODE_PREFIX + entity.getCode(), entity, CODE_TTL);
        log.debug("✅ Saved AuthCodeEntity for {}", entity.getAuthorizationId());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> codeToken = authorization.getToken(OAuth2AuthorizationCode.class);
        if (codeToken != null) {
            redisTemplate.delete(CODE_PREFIX + codeToken.getToken().getTokenValue());
        }
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (!AUTHORIZATION_CODE_TOKEN_TYPE.equals(tokenType)) return null;

        Object obj = redisTemplate.opsForValue().get(CODE_PREFIX + token);
        if (obj == null) return null;

        AuthCodeEntity entity = (obj instanceof AuthCodeEntity e)
                ? e
                : objectMapper.convertValue(obj, AuthCodeEntity.class);

        RegisteredClient client = clientRepository.findById(entity.getRegisteredClientId());
        if (client == null) return null;

        OAuth2AuthorizationCode authCode = new OAuth2AuthorizationCode(
                entity.getCode(),
                entity.getIssuedAt(),
                entity.getExpiresAt()
        );

        return OAuth2Authorization.withRegisteredClient(client)
                .id(entity.getAuthorizationId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(entity.getScopes())
                .attribute(OAuth2AuthorizationRequest.class.getName(), entity.getAuthorizationRequest())
                .attribute(Principal.class.getName(), entity.getPrincipal())
                .token(authCode)
                .build();
    }
}
